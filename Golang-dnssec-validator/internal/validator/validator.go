package validator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
	"github.com/ptudor/dnssec-validator/internal/rdap"
)

// EventCallback is called when validation events occur
type EventCallback func(event SSEEvent)

// Validator performs DNSSEC validation
type Validator struct {
	resolver      *dnspkg.Resolver
	anchors       *dnspkg.RootAnchors
	queryTimeout  time.Duration
	totalTimeout  time.Duration
	maxConcurrent int
	quickMode     bool   // true = query first responding NS only; false = query all
	queryType     uint16 // leaf record type to validate (default A) — R-083
	eventCallback EventCallback
	rdapClient    *rdap.Client
	// rootServers overrides the root-server address list when set. It exists
	// so a hermetic fixture can serve the root zone through the real
	// validation path (RA6X-050); production leaves it nil.
	rootServers []string
}

// rootServerAddresses returns the root-server addresses to query.
func (v *Validator) rootServerAddresses() []string {
	if len(v.rootServers) > 0 {
		return append([]string(nil), v.rootServers...)
	}
	return dnspkg.GetRootServers()
}

// NewValidator creates a new DNSSEC validator
func NewValidator(queryTimeout, totalTimeout time.Duration, maxConcurrent int, anchors *dnspkg.RootAnchors, recursiveResolver string) *Validator {
	return &Validator{
		resolver:      dnspkg.NewResolver(queryTimeout, recursiveResolver),
		anchors:       anchors,
		queryTimeout:  queryTimeout,
		totalTimeout:  totalTimeout,
		maxConcurrent: maxConcurrent,
		queryType:     dns.TypeA,
	}
}

// SetQuickMode enables quick mode (query first responding NS only)
func (v *Validator) SetQuickMode(quick bool) {
	v.quickMode = quick
}

// SetQueryType sets the leaf record type to validate (default A). Plumbs the
// documented `type` query parameter through to the leaf query and denial
// reasoning (R-083).
func (v *Validator) SetQueryType(t uint16) {
	if t == 0 {
		t = dns.TypeA
	}
	v.queryType = t
}

// leafType returns the configured leaf query type, defaulting to A.
func (v *Validator) leafType() uint16 {
	if v.queryType == 0 {
		return dns.TypeA
	}
	return v.queryType
}

// leafTypeName is the string form of the leaf query type (e.g. "A", "MX").
func (v *Validator) leafTypeName() string {
	if name, ok := dns.TypeToString[v.leafType()]; ok {
		return name
	}
	return "A"
}

// SupportedQueryType parses a record-type string into a dns type, restricted to
// the types this validator can meaningfully fetch and verify at the leaf. An
// empty string defaults to A; an unsupported type returns ok=false (R-083).
func SupportedQueryType(s string) (uint16, bool) {
	if s == "" {
		return dns.TypeA, true
	}
	t, ok := dns.StringToType[strings.ToUpper(s)]
	if !ok {
		return 0, false
	}
	switch t {
	case dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeTXT, dns.TypeNS,
		dns.TypeSOA, dns.TypeSRV, dns.TypeCAA, dns.TypePTR, dns.TypeNAPTR,
		dns.TypeCNAME, dns.TypeSPF:
		return t, true
	}
	return 0, false
}

// SetRDAPClient sets the RDAP client for out-of-band DS record verification
func (v *Validator) SetRDAPClient(client *rdap.Client) {
	v.rdapClient = client
}

// SetEventCallback sets the callback for validation events
func (v *Validator) SetEventCallback(cb EventCallback) {
	v.eventCallback = cb
}

// SetAnchors updates the trust anchors
func (v *Validator) SetAnchors(anchors *dnspkg.RootAnchors) {
	v.anchors = anchors
}

// emitEvent sends an event to the callback if set
func (v *Validator) emitEvent(eventType string, data interface{}) {
	if v.eventCallback != nil {
		v.eventCallback(SSEEvent{
			Type: eventType,
			Data: data,
		})
	}
}

// Validate performs DNSSEC validation for a domain
func (v *Validator) Validate(ctx context.Context, domain string) (*ValidationResult, error) {
	return v.validateWithCache(ctx, domain, 0, make(map[string]bool), make(map[string]*ZoneResult))
}

// ValidateWithDepth performs DNSSEC validation with CNAME recursion depth tracking
func (v *Validator) ValidateWithDepth(ctx context.Context, domain string, depth int) (*ValidationResult, error) {
	return v.validateWithCache(ctx, domain, depth, make(map[string]bool), make(map[string]*ZoneResult))
}

// validateWithCache performs DNSSEC validation with a cache of already-validated
// zones. visited holds the canonical CNAME owner/target names seen so far on this
// chain, so a loop is detected instead of silently terminating at the depth cap (R-034).
func (v *Validator) validateWithCache(ctx context.Context, domain string, depth int, visited map[string]bool, validatedZones map[string]*ZoneResult) (*ValidationResult, error) {
	const maxCNAMEDepth = 10

	start := time.Now()

	// Create result
	result := &ValidationResult{
		Domain:      NormalizeDomain(domain),
		QueryType:   v.leafTypeName(),
		Result:      StatusValidating,
		Chain:       make([]ZoneResult, 0),
		CNAMEChains: make([]CNAMEChainResult, 0),
		Timestamp:   start,
		Errors:      make([]string, 0),
		Warnings:    make([]string, 0),
	}

	// Emit start event (only for top-level)
	if depth == 0 {
		mode := "extended"
		if v.quickMode {
			mode = "quick"
		}
		v.emitEvent("start", StartEvent{
			Domain:    result.Domain,
			QueryType: result.QueryType,
			Timestamp: start,
			Mode:      mode,
		})
	}

	// Check anchors
	if v.anchors == nil || len(v.anchors.Anchors) == 0 {
		err := fmt.Errorf("no root trust anchors available")
		result.Result = StatusIndeterminate
		result.Errors = append(result.Errors, err.Error())
		v.emitEvent("error", ErrorEvent{
			Message: err.Error(),
			Fatal:   true,
		})
		return result, err
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, v.totalTimeout)
	defer cancel()

	// Discover actual zone cuts instead of assuming every label is a zone
	v.emitEvent("progress", ProgressEvent{
		Zone:   result.Domain,
		Action: "discovering zone cuts",
	})

	zones, err := v.resolver.DiscoverZoneCuts(ctx, domain)
	if err != nil {
		// Fall back to simple hierarchy if zone cut discovery fails
		zones = SplitIntoZoneHierarchy(domain)
		result.Warnings = append(result.Warnings, fmt.Sprintf("zone cut discovery failed, using simple hierarchy: %v", err))
	}

	// Validate each zone in order
	var lastStatus ValidationStatus = StatusSecure
	var parentDNSKEY []dnspkg.DNSKEYRecord // Track parent's DNSKEY for DS RRSIG verification
	ancestorInsecure := false              // sticky: once any ancestor is insecure, descendants cannot be secure (R-033)
	for _, zone := range zones {
		select {
		case <-ctx.Done():
			result.Result = StatusIndeterminate
			result.Errors = append(result.Errors, "validation timeout")
			v.emitEvent("error", ErrorEvent{
				Zone:    zone,
				Message: "validation timeout",
				Fatal:   true,
			})
			result.DurationMs = time.Since(start).Milliseconds()
			return result, ctx.Err()
		default:
		}

		// Check if this zone was already validated (e.g., from main chain when following CNAME)
		if cachedResult, ok := validatedZones[zone]; ok {
			// Reuse cached result - add to chain but don't emit duplicate zone event
			result.Chain = append(result.Chain, *cachedResult)

			// Update parent DNSKEY from cached result for next zone's DS verification
			parentDNSKEY = nextParentDNSKEY(parentDNSKEY, cachedResult)

			// Track overall status from cached result
			switch cachedResult.Status {
			case StatusBogus:
				lastStatus = StatusBogus
				result.Result = StatusBogus
				result.DurationMs = time.Since(start).Milliseconds()
				v.emitComplete(depth, result)
				return result, nil
			case StatusInsecure:
				ancestorInsecure = true
				if lastStatus == StatusSecure {
					lastStatus = StatusInsecure
				}
			case StatusIndeterminate:
				if lastStatus == StatusSecure || lastStatus == StatusInsecure {
					lastStatus = StatusIndeterminate
				}
			}
			continue
		}

		// Emit progress
		v.emitEvent("progress", ProgressEvent{
			Zone:   zone,
			Action: "validating",
		})

		// Validate this zone (pass parent DNSKEY for DS RRSIG verification, and
		// whether an ancestor is already insecure so a child below it stays insecure)
		zoneResult, err := v.validateZone(ctx, zone, zones, parentDNSKEY, ancestorInsecure)
		if err != nil {
			// Zone validation error
			zoneResult = NewZoneResult(zone)
			zoneResult.Status = StatusIndeterminate
			zoneResult.AddError(err.Error())
		}

		// Update parent DNSKEY for next zone's DS verification
		parentDNSKEY = nextParentDNSKEY(parentDNSKEY, zoneResult)

		// Cache the result for potential reuse
		validatedZones[zone] = zoneResult

		result.Chain = append(result.Chain, *zoneResult)

		// Emit zone event
		v.emitEvent("zone", ZoneEvent{
			Zone:       zone,
			Status:     zoneResult.Status,
			ZoneResult: zoneResult,
			QueryName:  result.Domain,
			Depth:      depth,
		})

		// Track overall status
		switch zoneResult.Status {
		case StatusBogus:
			lastStatus = StatusBogus
			// Stop validation on bogus
			result.Result = StatusBogus
			result.DurationMs = time.Since(start).Milliseconds()
			v.emitComplete(depth, result)
			return result, nil
		case StatusInsecure:
			ancestorInsecure = true
			if lastStatus == StatusSecure {
				lastStatus = StatusInsecure
			}
		case StatusIndeterminate:
			if lastStatus == StatusSecure || lastStatus == StatusInsecure {
				lastStatus = StatusIndeterminate
			}
		}
	}

	// Verify actual record RRSIG at the leaf zone (only if chain is secure).
	// The authenticated alias target (CNAME or DNAME) comes out of this step;
	// it is the ONLY thing alias traversal follows below (RA6X-015).
	var aliasTarget string
	leafZoneName := ""
	if len(zones) > 0 {
		leafZoneName = zones[len(zones)-1]
	}
	if lastStatus == StatusSecure && len(result.Chain) > 0 {
		leafZone := &result.Chain[len(result.Chain)-1]
		recordValidation := v.verifyActualRecord(ctx, domain, leafZone.Zone, leafZone.DNSKEY)
		if recordValidation != nil {
			leafZone.RecordValidation = recordValidation
			// A wildcard-synthesized answer without a verified closest-encloser proof is
			// not a fully verified denial of a direct match (RFC 4035 §5.3.4); surface it
			// rather than letting the chain read as fully verified on the record signature.
			if recordValidation.Wildcard && !recordValidation.WildcardProofVerified {
				leafZone.Warnings = append(leafZone.Warnings,
					fmt.Sprintf("wildcard-synthesized answer from %s lacks a verified closest-encloser proof of no direct match",
						recordValidation.WildcardSource))
			}
			// The cache holds ZONE authentication only. The per-name answer
			// validation stays on this request's copy of the zone result, so a
			// later name in the same zone (an alias hop) neither inherits nor
			// overwrites it (RA6X-022).
			// R-082: fold the leaf record's signature outcome into the overall verdict. A
			// secure chain over an answer whose RRSIG is missing/expired/forged (and which
			// is not a verified denial) is not secure — the caller reads result.Result, so
			// the record failure must move the verdict, not just the per-zone detail.
			if verdict, msg := recordValidationVerdict(recordValidation); verdict != StatusSecure {
				lastStatus = verdict
				if msg != "" {
					if verdict == StatusInsecure {
						// An authenticated opt-out conclusion is not a failure; record
						// it as a warning so the insecure verdict is explained (RA6X-012).
						result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %s", leafZone.Zone, msg))
						leafZone.Warnings = append(leafZone.Warnings, msg)
					} else {
						result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", leafZone.Zone, msg))
					}
				}
			}
			if lastStatus == StatusSecure && recordValidation.RRSIGVerified {
				aliasTarget = recordValidation.Target
			}
			// Re-emit the leaf zone now that its per-name record validation
			// exists, so a streaming client can reconcile the card it drew
			// from the earlier, leaf-less zone event (RA6X-022).
			v.emitEvent("zone", ZoneEvent{
				Zone:       leafZone.Zone,
				Status:     leafZone.Status,
				ZoneResult: leafZone,
				QueryName:  result.Domain,
				Depth:      depth,
			})
		}
	} else if lastStatus != StatusBogus && leafZoneName != "" {
		// No authenticated leaf exists below an insecure or indeterminate chain;
		// an alias there is still resolved (its target's status still bounds the
		// answer) from the Answer-section CNAME at the queried owner only.
		aliasTarget = v.discoverAliasTarget(ctx, domain, leafZoneName)
	}

	// Follow the alias, if any. An explicit CNAME query is complete once the
	// requested RRset is authenticated; traversal is not part of its verdict.
	// followAlias enforces the loop/depth guards internally (R-034), and a
	// hop whose target cannot be validated is indeterminate, never a silent
	// success (RA6X-015).
	if aliasTarget != "" && v.leafType() != dns.TypeCNAME {
		cnameResult := v.followAlias(ctx, domain, aliasTarget, depth, maxCNAMEDepth, visited, validatedZones)
		result.CNAMEChains = append(result.CNAMEChains, *cnameResult)

		// If the CNAME target is not secure, the overall result is not secure
		switch cnameResult.Result {
		case StatusBogus:
			lastStatus = StatusBogus
			result.Errors = append(result.Errors, fmt.Sprintf("CNAME target %s is bogus", cnameResult.Target))
		case StatusInsecure:
			if lastStatus == StatusSecure {
				lastStatus = StatusInsecure
				result.Warnings = append(result.Warnings, fmt.Sprintf("CNAME target %s is insecure", cnameResult.Target))
			}
		case StatusIndeterminate:
			if lastStatus == StatusSecure || lastStatus == StatusInsecure {
				lastStatus = StatusIndeterminate
				msg := fmt.Sprintf("CNAME target %s is indeterminate", cnameResult.Target)
				if cnameResult.Error != "" {
					msg = fmt.Sprintf("CNAME target %s could not be validated: %s", cnameResult.Target, cnameResult.Error)
				}
				result.Warnings = append(result.Warnings, msg)
			}
		}
	}

	result.Result = lastStatus
	result.DurationMs = time.Since(start).Milliseconds()

	v.emitComplete(depth, result)

	return result, nil
}

// emitComplete emits the terminal event for the TOP-LEVEL request only. A
// nested alias-target validation returns its outcome to the caller, which
// carries it as a CNAMEChainResult in the one terminal event (RA6X-022).
func (v *Validator) emitComplete(depth int, result *ValidationResult) {
	if depth != 0 {
		return
	}
	v.emitEvent("complete", CompleteEvent{
		Result:      result.Result,
		Chain:       result.Chain,
		CNAMEChains: result.CNAMEChains,
		DurationMs:  result.DurationMs,
		Errors:      result.Errors,
		Warnings:    result.Warnings,
	})
}

// nextParentDNSKEY decides which DNSKEY set to carry into the next (child)
// zone's DS verification after a zone in the walk resolves. A proven-insecure
// zone terminates the chain of trust, so its descendants must reach the
// insecure-ancestor branch of finalizeNoDSDelegation (empty parent keys) and
// read insecure — not be asked for a DS-absence proof that only the nearest
// SIGNED ancestor's keys could have produced. An indeterminate or bogus zone
// must NOT clear the keys: an unauthenticated parent would otherwise launder
// its children into insecure (fail closed).
func nextParentDNSKEY(prev []dnspkg.DNSKEYRecord, zr *ZoneResult) []dnspkg.DNSKEYRecord {
	if zr.Status == StatusInsecure {
		return nil
	}
	if len(zr.DNSKEY) > 0 {
		return zr.DNSKEY
	}
	return prev
}

// cnameGuard decides whether following domain→target must terminate. It returns a
// terminal CNAMEChainResult and true when the hop would loop (target already
// visited → bogus) or exceed maxDepth (indeterminate); otherwise it marks target
// visited and returns (nil, false) to proceed. (R-034)
func cnameGuard(domain, target string, depth, maxDepth int, visited map[string]bool) (*CNAMEChainResult, bool) {
	ct := canonicalizeName(target)
	if visited[ct] {
		return &CNAMEChainResult{
			Source: domain, Target: target, Result: StatusBogus,
			Error: fmt.Sprintf("CNAME loop detected: %s points back to an already-visited name %s", domain, target),
		}, true
	}
	if depth+1 >= maxDepth {
		return &CNAMEChainResult{
			Source: domain, Target: target, Result: StatusIndeterminate,
			Error: fmt.Sprintf("CNAME chain exceeded maximum depth (%d) at %s without resolving; terminal target not validated", maxDepth, target),
		}, true
	}
	visited[ct] = true
	return nil, false
}

// followAlias validates the authenticated alias target of domain and returns
// the hop's outcome. It follows exactly the target that leaf verification
// authenticated — no second, unauthenticated DNS lookup decides where to go
// (RA6X-015). It carries the canonical-name visited set and enforces loop and
// depth limits (R-034): a repeated owner/target is a CNAME loop (bogus), and a
// chain that would exceed maxDepth without resolving is depth-limited
// (indeterminate). A target whose validation fails outright is indeterminate,
// never reported as a successful completion.
func (v *Validator) followAlias(ctx context.Context, domain, target string, depth, maxDepth int, visited map[string]bool, validatedZones map[string]*ZoneResult) *CNAMEChainResult {
	// Record this owner name so a later hop back to it is detected as a loop.
	visited[canonicalizeName(domain)] = true

	v.emitEvent("cname", CNAMEEvent{
		Source: domain,
		Target: target,
	})

	if term, stop := cnameGuard(domain, target, depth, maxDepth, visited); stop {
		return term
	}

	v.emitEvent("progress", ProgressEvent{
		Zone:   target,
		Action: "following CNAME (reusing validated zones)",
	})

	// Validate the CNAME target, reusing already-validated zones
	targetResult, err := v.validateWithCache(ctx, target, depth+1, visited, validatedZones)
	if err != nil {
		return &CNAMEChainResult{
			Source: domain,
			Target: target,
			Result: StatusIndeterminate,
			Chain:  nil,
			Error:  fmt.Sprintf("alias target validation failed: %v", err),
		}
	}

	return &CNAMEChainResult{
		Source: domain,
		Target: target,
		Result: targetResult.Result,
		Chain:  targetResult.Chain,
	}
}

// discoverAliasTarget finds the alias target of domain when no authenticated
// leaf exists (the chain is insecure or indeterminate). It asks the leaf
// zone's servers for the queried type and accepts only an Answer-section
// CNAME owned by the queried name; CNAMEs at other owners or in other
// sections are never followed (RA6X-015). The result is unauthenticated,
// which is fine: the answer can be no better than the chain above it.
func (v *Validator) discoverAliasTarget(ctx context.Context, domain, leafZone string) string {
	nsRecords, err := v.resolver.ResolveNSWithAddresses(ctx, leafZone)
	if err != nil || len(nsRecords) == 0 {
		return ""
	}
	var nsAddresses []string
	for _, ns := range nsRecords {
		for _, addr := range ns.Addresses {
			nsAddresses = append(nsAddresses, addr.String())
		}
	}
	for _, addr := range nsAddresses {
		select {
		case <-ctx.Done():
			return ""
		default:
		}
		qr, err := v.resolver.QueryRecordAuthoritative(ctx, addr, domain, v.leafType())
		if err != nil || qr == nil || qr.Error != "" || qr.RCode != dns.RcodeSuccess {
			continue
		}
		if cnames := answerCNAMEsOwnedBy(qr.CNAME, domain); len(cnames) > 0 {
			return cnames[0].Target
		}
		return ""
	}
	return ""
}

// queryLeafAllServers queries the leaf record from the authoritative servers.
// In quick mode it returns the first usable answer. In extended mode it queries
// EVERY server, returns the first usable answer whose positive data verifies
// under the zone's keys (or the first usable answer when none does, so the
// failure is reported), and flags every other server whose answer differs by
// content or whose signature fails — the "query every NS, flag inconsistencies"
// feature (R-100, RA6X-018). Disagreement here is diagnostic: it never changes
// the verdict that the chosen answer earns on its own.
func (v *Validator) queryLeafAllServers(ctx context.Context, nsAddresses []string, domain, zone string, dnskeys []dnspkg.DNSKEYRecord) (*dnspkg.QueryResult, []string) {
	var usable []*dnspkg.QueryResult
	for _, addr := range nsAddresses {
		select {
		case <-ctx.Done():
			break
		default:
		}
		result, err := v.resolver.QueryRecordAuthoritative(ctx, addr, domain, v.leafType())
		if err != nil || result == nil || result.Error != "" {
			continue
		}
		usable = append(usable, result)
		if v.quickMode {
			return result, nil
		}
	}
	if len(usable) == 0 {
		return nil, nil
	}

	// Pick the first answer whose positive data verifies; a server serving
	// the right data with a broken signature must not block a valid path.
	chosen := usable[0]
	for _, qr := range usable {
		if v.leafSignatureError(qr, domain, zone, dnskeys) == nil {
			chosen = qr
			break
		}
	}

	chosenFP := v.leafFingerprint(chosen)
	var disagreements []string
	for _, qr := range usable {
		if qr == chosen {
			continue
		}
		if fp := v.leafFingerprint(qr); fp != chosenFP {
			disagreements = append(disagreements, fmt.Sprintf(
				"%s (%s) returned a different %s answer (%s) than %s (%s) (%s)",
				qr.Server, qr.IP, v.leafTypeName(), qr.RCodeName,
				chosen.Server, chosen.IP, chosen.RCodeName))
			continue
		}
		if err := v.leafSignatureError(qr, domain, zone, dnskeys); err != nil {
			disagreements = append(disagreements, fmt.Sprintf(
				"%s (%s) returned the same %s answer as %s (%s) but its signature does not verify: %v",
				qr.Server, qr.IP, v.leafTypeName(), chosen.Server, chosen.IP, err))
		}
	}
	return chosen, disagreements
}

// leafSignatureError verifies the positive data in a leaf answer (the queried
// type at the owner, or the CNAME at the owner) under the zone's keys. Denial
// answers carry no positive RRset and are not judged here; they return nil.
func (v *Validator) leafSignatureError(qr *dnspkg.QueryResult, domain, zone string, dnskeys []dnspkg.DNSKEYRecord) error {
	if qr.RCode != dns.RcodeSuccess || len(qr.RawResponse) == 0 {
		return nil
	}
	switch {
	case answerHasTypeAt(qr.RawResponse, v.leafType(), domain):
		_, err := VerifyRRsetFromResponse(qr.RawResponse, v.leafType(), dnskeys, domain, zone, true)
		return err
	case len(answerCNAMEsOwnedBy(qr.CNAME, domain)) > 0:
		if dnameAncestorInAnswer(qr, domain) != "" {
			return nil // authenticated through the DNAME path instead
		}
		_, err := VerifyRRsetFromResponse(qr.RawResponse, dns.TypeCNAME, dnskeys, domain, zone, true)
		return err
	}
	return nil
}

// leafFingerprint builds a TTL-insensitive canonical summary of a server's
// answer for the leaf type (RCODE plus the sorted, de-duplicated leaf/CNAME
// rdata), so answers can be compared across servers without flagging benign
// TTL differences. Comparison is type-aware (RA6X-018): owner names and the
// domain names inside RDATA are case-insensitive in DNS and are lowercased,
// while case-sensitive RDATA such as TXT is retained as served.
func (v *Validator) leafFingerprint(qr *dnspkg.QueryResult) string {
	parts := []string{qr.RCodeName}
	if len(qr.RawResponse) > 0 {
		var msg dns.Msg
		if err := msg.Unpack(qr.RawResponse); err == nil {
			seen := make(map[string]bool)
			var rrs []string
			for _, rr := range msg.Answer {
				t := rr.Header().Rrtype
				if t != v.leafType() && t != dns.TypeCNAME {
					continue
				}
				c := canonicalRRString(rr)
				if !seen[c] {
					seen[c] = true
					rrs = append(rrs, c)
				}
			}
			sort.Strings(rrs)
			parts = append(parts, rrs...)
		}
	}
	return strings.Join(parts, "|")
}

// canonicalRRString renders a record for comparison: TTL zeroed, the owner
// and every domain name in the RDATA lowercased (RFC 4034 §6.2 canonical
// form), other RDATA byte-for-byte as served.
func canonicalRRString(rr dns.RR) string {
	c := dns.Copy(rr)
	h := c.Header()
	h.Name = dns.CanonicalName(h.Name)
	h.Ttl = 0
	switch v := c.(type) {
	case *dns.CNAME:
		v.Target = dns.CanonicalName(v.Target)
	case *dns.DNAME:
		v.Target = dns.CanonicalName(v.Target)
	case *dns.NS:
		v.Ns = dns.CanonicalName(v.Ns)
	case *dns.PTR:
		v.Ptr = dns.CanonicalName(v.Ptr)
	case *dns.MX:
		v.Mx = dns.CanonicalName(v.Mx)
	case *dns.SRV:
		v.Target = dns.CanonicalName(v.Target)
	case *dns.SOA:
		v.Ns = dns.CanonicalName(v.Ns)
		v.Mbox = dns.CanonicalName(v.Mbox)
	case *dns.NAPTR:
		v.Replacement = dns.CanonicalName(v.Replacement)
	}
	return c.String()
}

// verifyActualRecord queries and verifies the actual record (A, AAAA, etc.) RRSIG
func (v *Validator) verifyActualRecord(ctx context.Context, domain, zone string, dnskeys []dnspkg.DNSKEYRecord) *RecordValidation {
	if len(dnskeys) == 0 {
		return nil // Can't verify without zone DNSKEY
	}

	// Get nameservers for the zone
	nsRecords, err := v.resolver.ResolveNSWithAddresses(ctx, zone)
	if err != nil || len(nsRecords) == 0 {
		return &RecordValidation{
			Name:       NormalizeDomain(domain),
			RecordType: v.leafTypeName(),
			Error:      fmt.Sprintf("failed to resolve nameservers: %v", err),
		}
	}

	// Collect NS addresses
	var nsAddresses []string
	for _, ns := range nsRecords {
		for _, addr := range ns.Addresses {
			nsAddresses = append(nsAddresses, addr.String())
		}
	}

	// Query the leaf record type from authoritative servers. In extended mode we
	// query every server and flag per-server disagreement (R-100); the first
	// usable answer is used for the cryptographic verification below.
	queryResult, disagreements := v.queryLeafAllServers(ctx, nsAddresses, domain, zone, dnskeys)

	if queryResult == nil {
		return &RecordValidation{
			Name:       NormalizeDomain(domain),
			RecordType: v.leafTypeName(),
			Error:      fmt.Sprintf("failed to query %s record from authoritative servers", v.leafTypeName()),
		}
	}

	validation := &RecordValidation{
		Name:                NormalizeDomain(domain),
		RecordType:          v.leafTypeName(),
		ServerDisagreements: disagreements,
	}

	// Check for NXDOMAIN/NODATA with NSEC/NSEC3 proofs. Only Answer/Authority
	// records are denial candidates; Additional is never evidence (RA6X-007).
	if isDenialForType(queryResult, v.leafType()) {
		nsecCands := denialNSECCandidates(queryResult.NSEC)
		nsec3Cands := denialNSEC3Candidates(queryResult.NSEC3)
		// Check for denial proofs if this is NXDOMAIN or NODATA
		if len(nsecCands) > 0 {
			// Verify NSEC denial proof with full RRSIG verification
			proof := VerifyNSECDenialWithRRSIG(domain, v.leafType(), nsecCands, dnskeys, zone, queryResult.RawResponse, queryResult.RCode)
			validation.DenialProof = proof
			if proof.Verified {
				validation.RRSIGVerified = true
			} else if proof.Error != "" {
				validation.Error = proof.Error
			}
			return validation
		} else if len(nsec3Cands) > 0 {
			// Verify NSEC3 denial proof with full RRSIG verification
			proof := VerifyNSEC3DenialWithRRSIG(domain, v.leafType(), nsec3Cands, dnskeys, zone, queryResult.RawResponse, queryResult.RCode)
			validation.DenialProof = proof
			if proof.Verified {
				validation.RRSIGVerified = true
			} else if proof.Error != "" {
				validation.Error = proof.Error
			}
			return validation
		}
	}

	// Positive data is authenticated from the Answer section at the queried
	// owner only; signatures and aliases parked in other sections or at other
	// owners are diagnostics, never candidates (RA6X-007). Every covering
	// signature at that owner is tried as an indivisible candidate against
	// every eligible zone key sharing its tag (RA6X-009/017): a signature that
	// is expired, names an unknown key, or fails cryptographically does not
	// prevent a later valid one from authenticating the RRset, and only the
	// signature that actually verified supplies the metadata used below.
	leafCNAMEs := answerCNAMEsOwnedBy(queryResult.CNAME, domain)

	// RFC 6672 §2.2: a DNAME whose substitution would exceed the name length
	// limit is answered with YXDOMAIN and no CNAME. The redirection itself may
	// still be authenticated; the queried name simply cannot be resolved.
	if queryResult.RCode == dns.RcodeYXDomain {
		if dnameOwner := dnameAncestorInAnswer(queryResult, domain); dnameOwner != "" {
			return v.verifyDNAMEAnswer(validation, domain, zone, dnameOwner, leafCNAMEs, queryResult, dnskeys)
		}
		validation.Error = fmt.Sprintf("YXDOMAIN for %s without a DNAME in the answer", domain)
		return validation
	}

	if answerHasTypeAt(queryResult.RawResponse, v.leafType(), domain) {
		verified, err := VerifyRRsetFromResponse(queryResult.RawResponse, v.leafType(), dnskeys, domain, zone, true)
		if err != nil {
			validation.Error = fmt.Sprintf("%s record RRSIG verification failed: %v", v.leafTypeName(), err)
			return validation
		}
		v.recordVerifiedLeaf(validation, verified, domain, zone, queryResult, dnskeys)
		return validation
	}

	if len(leafCNAMEs) > 0 {
		// A CNAME synthesized from a DNAME (RFC 6672 §3.2) carries no signature
		// of its own; the DNAME RRset is what is authenticated (RA6X-014).
		if dnameOwner := dnameAncestorInAnswer(queryResult, domain); dnameOwner != "" {
			return v.verifyDNAMEAnswer(validation, domain, zone, dnameOwner, leafCNAMEs, queryResult, dnskeys)
		}
		// The answer is an alias: authenticate the CNAME RRset at the owner.
		validation.RecordType = "CNAME"
		verified, err := VerifyRRsetFromResponse(queryResult.RawResponse, dns.TypeCNAME, dnskeys, domain, zone, true)
		if err != nil {
			validation.Error = fmt.Sprintf("CNAME RRSIG verification failed: %v", err)
			return validation
		}
		v.recordVerifiedLeaf(validation, verified, domain, zone, queryResult, dnskeys)
		return validation
	}

	validation.Error = fmt.Sprintf("no %s RRset or CNAME for %s in the answer and no NSEC/NSEC3 denial records", v.leafTypeName(), domain)
	return validation
}

// recordVerifiedLeaf records a cryptographically verified leaf (or CNAME) RRset
// on validation. Every field it derives — signing key tag, record count, the
// alias target and the wildcard decision — comes from the exact records and
// signature that verified, never from another record in the response
// (RA6X-009, RA6X-015).
func (v *Validator) recordVerifiedLeaf(validation *RecordValidation, verified *VerifiedRRset, domain, zone string, queryResult *dnspkg.QueryResult, dnskeys []dnspkg.DNSKEYRecord) {
	validation.RRSIGVerified = true
	validation.SigningKeyTag = verified.Signature.KeyTag
	validation.RecordCount = len(verified.Records)
	if verified.Type == dns.TypeCNAME {
		for _, rr := range verified.Records {
			if c, ok := rr.(*dns.CNAME); ok {
				validation.Target = c.Target
				break
			}
		}
	}
	sig := dnspkg.RRSIGFromRR(verified.Signature, dnspkg.SectionAnswer, time.Now())
	v.verifyWildcard(validation, domain, zone, sig, queryResult, dnskeys)
}

// dnameAncestorInAnswer returns the owner of an Answer-section DNAME that is a
// proper ancestor of qname, or "" when the answer carries no such redirection.
func dnameAncestorInAnswer(qr *dnspkg.QueryResult, qname string) string {
	want := dns.CanonicalName(qname)
	for _, d := range qr.DNAME {
		if !dnspkg.InSection(d.Section, dnspkg.SectionAnswer) {
			continue
		}
		owner := dns.CanonicalName(d.Owner)
		if owner != want && dns.IsSubDomain(owner, want) {
			return owner
		}
	}
	return ""
}

// substituteDNAME applies RFC 6672 §2.2 to qname: the DNAME owner suffix is
// replaced by target. It fails when the result would exceed the DNS name
// length limit (the YXDOMAIN condition).
func substituteDNAME(qname, owner, target string) (string, error) {
	qname = dns.CanonicalName(qname)
	owner = dns.CanonicalName(owner)
	if owner == qname || !dns.IsSubDomain(owner, qname) {
		return "", fmt.Errorf("%s is not below DNAME owner %s", qname, owner)
	}
	qLabels := dns.SplitDomainName(qname)
	oLabels := dns.SplitDomainName(owner)
	prefix := qLabels[:len(qLabels)-len(oLabels)]
	synthesized := dns.Fqdn(strings.Join(append(prefix, strings.TrimSuffix(dns.Fqdn(target), ".")), "."))
	if target == "." || dns.Fqdn(target) == "." {
		synthesized = dns.Fqdn(strings.Join(prefix, "."))
	}
	// Wire length is the presentation length plus the root label; RFC 1035
	// §2.3.4 caps it at 255 octets.
	if _, ok := dns.IsDomainName(synthesized); !ok || len(synthesized)+1 > 255 {
		return "", fmt.Errorf("DNAME substitution of %s by %s -> %s exceeds the DNS name length limit (RFC 6672 §2.2, YXDOMAIN)", qname, owner, target)
	}
	return synthesized, nil
}

// verifyDNAMEAnswer authenticates a DNAME redirection: the DNAME RRset at
// dnameOwner must verify under this zone's keys, and the CNAME served at the
// queried name must be exactly the RFC 6672 substitution of the queried name
// by that DNAME. The synthesized CNAME itself is unsigned by design; nothing
// else in the answer may stand in for it (RA6X-014).
func (v *Validator) verifyDNAMEAnswer(validation *RecordValidation, domain, zone, dnameOwner string, cnames []dnspkg.CNAMERecord, queryResult *dnspkg.QueryResult, dnskeys []dnspkg.DNSKEYRecord) *RecordValidation {
	validation.RecordType = "DNAME"
	validation.SynthesizedFrom = dnameOwner

	verified, err := VerifyRRsetFromResponse(queryResult.RawResponse, dns.TypeDNAME, dnskeys, dnameOwner, zone, true)
	if err != nil {
		validation.Error = fmt.Sprintf("DNAME RRSIG verification failed for %s: %v", dnameOwner, err)
		return validation
	}
	var target string
	for _, rr := range verified.Records {
		if d, ok := rr.(*dns.DNAME); ok {
			if target != "" {
				validation.Error = fmt.Sprintf("DNAME RRset at %s holds more than one record (RFC 6672 §2.4)", dnameOwner)
				return validation
			}
			target = d.Target
		}
	}
	if target == "" {
		validation.Error = fmt.Sprintf("verified DNAME RRset at %s holds no DNAME record", dnameOwner)
		return validation
	}

	expected, err := substituteDNAME(domain, dnameOwner, target)
	if err != nil {
		// The DNAME RRset is authenticated but the redirection cannot be
		// applied to this name; report the authenticated reason (YXDOMAIN).
		validation.Error = fmt.Sprintf("authenticated DNAME %s -> %s cannot be applied: %v", dnameOwner, target, err)
		return validation
	}
	if queryResult.RCode == dns.RcodeYXDomain {
		validation.Error = fmt.Sprintf("authenticated DNAME %s -> %s answered YXDOMAIN although the substitution %s fits the name length limit", dnameOwner, target, expected)
		return validation
	}
	if len(cnames) != 1 || dns.CanonicalName(cnames[0].Target) != dns.CanonicalName(expected) {
		got := make([]string, 0, len(cnames))
		for _, c := range cnames {
			got = append(got, c.Target)
		}
		validation.Error = fmt.Sprintf("synthesized CNAME target %v does not match the DNAME substitution %s -> %s of %s (expected %s)", got, dnameOwner, target, domain, expected)
		return validation
	}

	validation.RRSIGVerified = true
	validation.SigningKeyTag = verified.Signature.KeyTag
	validation.RecordCount = 1
	validation.Target = expected
	sig := dnspkg.RRSIGFromRR(verified.Signature, dnspkg.SectionAnswer, time.Now())
	v.verifyWildcard(validation, dnameOwner, zone, sig, queryResult, dnskeys)
	return validation
}

// isDenialForType reports whether qr is a denial of existence (NXDOMAIN or
// NODATA) for qtype, as opposed to a positive answer. An RFC-compliant
// wildcard-expanded positive answer also carries NSEC/NSEC3 records — the
// no-closer-match proof (RFC 4035 §3.1.3.3) — so the presence of denial
// records alone must not divert a response that answers the query into the
// NODATA verification path; only a CNAME-free NOERROR response whose answer
// section is empty for the queried type is a NODATA candidate.
func isDenialForType(qr *dnspkg.QueryResult, qtype uint16) bool {
	if qr.RCode == dns.RcodeNameError {
		return true
	}
	return qr.RCode == dns.RcodeSuccess && len(qr.CNAME) == 0 && !answerContainsType(qr, qtype)
}

// answerContainsType reports whether the response's ANSWER section holds at
// least one record of the given type.
func answerContainsType(qr *dnspkg.QueryResult, qtype uint16) bool {
	for _, t := range qr.AnswerTypes {
		if t == qtype {
			return true
		}
	}
	return false
}

// leafSignerMatchesZone reports whether a leaf RRSIG's signer name is the zone
// that should have signed it. A leaf answer (A/AAAA/CNAME/…) must be signed by a
// key in its own zone; a signature by any other name is rejected as
// defense-in-depth atop the cryptographic key-tag match. Both the A and CNAME
// verification paths share this one rule so they cannot drift apart (R-096).
func leafSignerMatchesZone(signerName, zone string) bool {
	// DNS names are case-insensitive (RFC 4034 canonicalization lowercases before
	// signing), so compare canonical FQDNs — but require exact name equality, not
	// a suffix/subdomain match (R-040).
	return dns.CanonicalName(signerName) == dns.CanonicalName(zone)
}

// verifyWildcard checks the RFC 4035 §5.3.4 / RFC 5155 §8.8 requirement that a
// wildcard-synthesized answer is accompanied by an authenticated proof that the queried
// name has no exact (non-wildcard) match. It records the outcome on validation. A
// signature-valid answer is only a complete proof of a wildcard expansion when this
// no-exact-match proof is also present and cryptographically verified, so callers must
// not represent a wildcard answer as fully verified on the record signature alone.
func (v *Validator) verifyWildcard(validation *RecordValidation, qname, zone string, rrsig dnspkg.RRSIGRecord, queryResult *dnspkg.QueryResult, dnskeys []dnspkg.DNSKEYRecord) {
	wildcard := DetectWildcardSynthesis(qname, rrsig)
	if wildcard == "" {
		return // not wildcard-synthesized
	}

	validation.Wildcard = true
	validation.WildcardSource = wildcard

	// Authenticate the denial records first: only NSEC/NSEC3 RRsets whose
	// signatures verified may prove the absence of an exact match, and only
	// Answer/Authority records are candidates (RA6X-007).
	nsecCands := denialNSECCandidates(queryResult.NSEC)
	nsec3Cands := denialNSEC3Candidates(queryResult.NSEC3)
	var authNSEC []dnspkg.NSECRecord
	var authNSEC3 []dnspkg.NSEC3Record
	var cryptoErr error
	switch {
	case len(nsecCands) > 0:
		verified, _, err := VerifyDenialRRsetsFromResponse(queryResult.RawResponse, dns.TypeNSEC, dnskeys, zone)
		if err != nil {
			cryptoErr = err
		} else {
			authNSEC = nsecRecordsFromVerified(verified)
		}
	case len(nsec3Cands) > 0:
		verified, _, err := VerifyDenialRRsetsFromResponse(queryResult.RawResponse, dns.TypeNSEC3, dnskeys, zone)
		if err != nil {
			cryptoErr = err
		} else {
			authNSEC3 = nsec3RecordsFromVerified(verified)
		}
	}
	if cryptoErr != nil {
		proof := &NSECProof{
			ProofType:    "wildcard",
			ResponseType: "WILDCARD",
			Records:      make([]string, 0),
			Error:        fmt.Sprintf("wildcard denial RRSIG cryptographic verification failed: %v", cryptoErr),
		}
		validation.WildcardProof = proof
		if validation.Error == "" {
			validation.Error = fmt.Sprintf("wildcard answer from %s: %s", wildcard, proof.Error)
		}
		return
	}

	proof := VerifyWildcardDenial(qname, rrsig.Labels, authNSEC, authNSEC3)
	validation.WildcardProof = proof

	if !proof.Verified {
		// The covering NSEC/NSEC3 that proves no direct match is missing.
		if validation.Error == "" {
			if proof.Error != "" {
				validation.Error = fmt.Sprintf("wildcard answer from %s lacks a verified no-exact-match proof: %s", wildcard, proof.Error)
			} else {
				validation.Error = fmt.Sprintf("wildcard answer from %s lacks a verified no-exact-match proof", wildcard)
			}
		}
		return
	}

	validation.WildcardProofVerified = true
}

// recordValidationVerdict classifies a leaf RecordValidation into the verdict it should
// contribute (R-082). A verified record signature or verified denial keeps the zone
// secure; an unqueryable answer is indeterminate; a missing/expired/forged signature or
// an unverifiable denial is bogus. A wildcard-synthesized answer is secure only when BOTH
// its data RRSIG AND its required no-exact-match NSEC/NSEC3 proof verified (R-026,
// RFC 4035 §5.3.4); a missing/forged/incomplete wildcard proof is bogus (or
// indeterminate if the whole response could not be fetched).
func recordValidationVerdict(rv *RecordValidation) (ValidationStatus, string) {
	if rv == nil {
		return StatusSecure, ""
	}

	// R-026: a wildcard-synthesized positive answer whose data signature verified but
	// whose no-exact-match proof did NOT verify must not be reported secure.
	if rv.Wildcard && rv.RRSIGVerified && !rv.WildcardProofVerified {
		msg := rv.Error
		if msg == "" {
			msg = "wildcard answer lacks a verified no-exact-match (NSEC/NSEC3) proof"
		}
		if isUnqueryableRecordError(msg) {
			return StatusIndeterminate, msg
		}
		return StatusBogus, msg
	}

	if rv.RRSIGVerified {
		// RA6X-012: an authenticated proof that rests on an opt-out NSEC3 cover
		// of the next closer name cannot exclude an unsigned delegation there.
		// The signatures verified, but the conclusion is insecure, not secure
		// (RFC 5155 §9.2).
		if rv.DenialProof != nil && rv.DenialProof.Verified && rv.DenialProof.OptOut {
			return StatusInsecure, fmt.Sprintf("denial rests on an opt-out NSEC3 covering %s: an unsigned delegation may exist, so the answer is insecure rather than secure (RFC 5155 §9.2)", rv.DenialProof.NextCloser)
		}
		if rv.Wildcard && rv.WildcardProof != nil && rv.WildcardProof.Verified && rv.WildcardProof.OptOut {
			return StatusInsecure, fmt.Sprintf("wildcard proof rests on an opt-out NSEC3 covering %s: an unsigned delegation may exist, so the answer is insecure rather than secure (RFC 5155 §9.2)", rv.WildcardProof.NextCloser)
		}
		return StatusSecure, ""
	}

	if isUnqueryableRecordError(rv.Error) {
		msg := rv.Error
		if msg == "" {
			msg = "record could not be queried from authoritative servers"
		}
		return StatusIndeterminate, msg
	}

	msg := rv.Error
	if msg == "" && rv.DenialProof != nil {
		msg = rv.DenialProof.Error
	}
	if msg == "" {
		msg = "record RRSIG could not be verified"
	}
	return StatusBogus, msg
}

// isUnqueryableRecordError reports whether a RecordValidation error reflects an inability
// to obtain the answer (a resolver/query failure) rather than a signature failure. The
// former is indeterminate; the latter is bogus.
func isUnqueryableRecordError(errText string) bool {
	return strings.HasPrefix(errText, "failed to resolve nameservers") ||
		strings.HasPrefix(errText, "failed to query") ||
		// An authenticated DNAME whose substitution cannot be formed (YXDOMAIN)
		// is not a forgery; the name simply has no resolvable answer (RA6X-014).
		strings.Contains(errText, "YXDOMAIN")
}

// validateZone validates a single zone
// parentDNSKEY is used for DS RRSIG verification (nil for root zone)
func (v *Validator) validateZone(ctx context.Context, zone string, hierarchy []string, parentDNSKEY []dnspkg.DNSKEYRecord, parentInsecure bool) (*ZoneResult, error) {
	result := NewZoneResult(zone)
	start := time.Now()

	// Get nameservers for this zone
	var nsAddresses []string
	if zone == "." {
		// Use root servers
		nsAddresses = v.rootServerAddresses()
		// Create nameserver entries for root servers
		nsResult := NameserverResult{
			Name:      "root-servers",
			Addresses: make([]AddressResult, 0, len(nsAddresses)),
		}
		for _, addr := range nsAddresses {
			nsResult.Addresses = append(nsResult.Addresses, AddressResult{
				IP:     addr,
				Status: StatusValidating,
			})
		}
		result.Nameservers = append(result.Nameservers, nsResult)
	} else {
		// Resolve NS for the zone
		nsRecords, err := v.resolver.ResolveNSWithAddresses(ctx, zone)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve NS for %s: %w", zone, err)
		}

		// Collect all addresses
		for _, ns := range nsRecords {
			nsResult := NameserverResult{
				Name:      ns.Name,
				Addresses: make([]AddressResult, 0),
			}
			// RA6X-019: a nameserver whose address lookup partly failed is not
			// fully enumerated; say so rather than silently querying less.
			for _, problem := range ns.LookupErrors {
				result.Warnings = append(result.Warnings, fmt.Sprintf("nameserver %s: %s", ns.Name, problem))
			}
			for _, addr := range ns.Addresses {
				nsAddresses = append(nsAddresses, addr.String())
				nsResult.Addresses = append(nsResult.Addresses, AddressResult{
					IP:     addr.String(),
					Status: StatusValidating,
				})
			}
			result.Nameservers = append(result.Nameservers, nsResult)
		}
	}

	if len(nsAddresses) == 0 {
		return nil, fmt.Errorf("no nameserver addresses found for %s", zone)
	}

	// Query DNSKEY from ALL nameservers in parallel
	v.emitEvent("progress", ProgressEvent{
		Zone:   zone,
		Action: fmt.Sprintf("querying %d nameservers", len(nsAddresses)),
	})

	serverResults := v.ValidateMultipleServers(ctx, zone, nsAddresses)

	// applyServerResults copies the per-server outcomes onto the nameserver
	// entries. It runs again after authentication so each address shows
	// whether ITS answer chained to the trust anchor (RA6X-018), not merely
	// whether it answered.
	applyServerResults := func() {
		serverResultMap := make(map[string]AddressResult)
		for _, sr := range serverResults {
			serverResultMap[sr.IP] = sr
		}
		for i, ns := range result.Nameservers {
			for j, addr := range ns.Addresses {
				if sr, ok := serverResultMap[addr.IP]; ok {
					result.Nameservers[i].Addresses[j] = sr
				}
			}
		}
	}
	applyServerResults()

	// Usable responses answered NOERROR; those carrying an Answer-section
	// DNSKEY RRset owned by the zone are candidates for the chain.
	var usable, withKeys []int
	for i := range serverResults {
		if serverResults[i].Response == nil {
			continue
		}
		usable = append(usable, i)
		if len(answerDNSKEYsOwnedBy(serverResults[i].Response.DNSKEY, zone)) > 0 {
			withKeys = append(withKeys, i)
		}
	}

	if len(usable) == 0 {
		result.Status = StatusIndeterminate
		result.AddError("failed to query DNSKEY from any nameserver")
		return result, nil
	}

	// Diagnostics come from the first response carrying keys, else the first
	// usable one (an unsigned zone's denial records live there). The zone's
	// DNSKEY RRset is the Answer-section set owned by the zone; keys in other
	// sections or at other owners are never part of it (RA6X-007). The full
	// parsed set with its section metadata remains visible per server in
	// Nameservers[].Addresses[].Response.
	diag := serverResults[usable[0]].Response
	if len(withKeys) > 0 {
		diag = serverResults[withKeys[0]].Response
	}
	result.DNSKEY = answerDNSKEYsOwnedBy(diag.DNSKEY, zone)
	result.RRSIG = diag.RRSIG
	result.NSEC = diag.NSEC
	result.NSEC3 = diag.NSEC3

	// markUsable sets every NOERROR server to a final per-server status when
	// the zone's verdict does not rest on per-server authentication.
	markUsable := func(status ValidationStatus, reason string) {
		for _, i := range usable {
			serverResults[i].Status = status
			if reason != "" {
				serverResults[i].Error = reason
			}
		}
		applyServerResults()
	}

	// R-033: below an insecure (proven-unsigned) ancestor there is no authenticated
	// chain back to the configured root, so any DS/DNSKEY observed at this child is
	// unauthenticated and cannot make it secure — nor is it bogus. Keep the result
	// insecure; the DNSKEY records above remain as diagnostics. (A nil parentDNSKEY
	// alone is ambiguous — root vs insecure ancestor vs missing parent key — hence an
	// explicit flag is threaded in rather than inferred from nil keys.)
	if zone != "." && parentInsecure {
		result.Status = StatusInsecure
		result.Warnings = append(result.Warnings,
			"delegation is below an insecure (unsigned) ancestor; no authenticated chain to the root — treated as insecure")
		markUsable(StatusInsecure, "")
		return result, nil
	}

	// Check if zone is signed
	if len(withKeys) == 0 {
		// Zone might be insecure - check for DS in parent
		if zone != "." {
			parentZone := parentZoneFromHierarchy(zone, hierarchy)
			ds, err := v.queryDSFromParentWithValidation(ctx, zone, parentZone, nsAddresses, parentDNSKEY)
			if err != nil {
				// A query failure is not evidence of an insecure delegation; do not
				// silently downgrade — report it as indeterminate.
				result.Status = StatusIndeterminate
				result.AddError(fmt.Sprintf("failed to query DS from parent: %v", err))
				return result, nil
			}
			result.Disagreements = append(result.Disagreements, ds.Disagreements...)
			if len(ds.Observed) == 0 {
				// No DS in parent: insecure delegation only if the parent authenticatedly
				// proves the DS RRset is absent (R-081 downgrade guard).
				v.finalizeNoDSDelegation(result, zone, parentZone, parentDNSKEY, ds.Response)
				if result.Status == StatusInsecure {
					markUsable(StatusInsecure, "")
				} else {
					markUsable(result.Status, "zone served no DNSKEY RRset")
				}
				return result, nil
			}
			// DS exists but no DNSKEY = bogus
			result.Status = StatusBogus
			result.AddError("DS exists in parent but zone has no DNSKEY")
			markUsable(StatusBogus, "DS exists in parent but this server served no DNSKEY RRset")
			return result, nil
		}
		// Root without DNSKEY is bogus
		result.Status = StatusBogus
		result.AddError("root zone has no DNSKEY")
		markUsable(StatusBogus, "served no DNSKEY RRset for the root")
		return result, nil
	}

	// Establish the trust source for this zone: the pinned anchors for the root,
	// the parent's authenticated DS RRset otherwise. The DNSKEY RRset MUST be
	// signed by a key this source authenticates (RFC 4035 §5.2), so the source
	// is fixed first and its key identity is then required of every server's
	// DNSKEY response below.
	var trust func(keys []dnspkg.DNSKEYRecord) (*ChainLink, []dnspkg.DNSKEYRecord, error)

	if zone == "." {
		// Root zone - verify DNSKEYs against the trust anchors (digest match).
		// Only currently-active, exactly pinned anchors may establish root trust;
		// any other loaded entry is diagnostic data (RA6X-008).
		activeAnchors := dnspkg.GetActivePinnedAnchors(v.anchors)
		if len(activeAnchors) == 0 {
			// No currently-active pinned trust anchor (all future-dated, expired,
			// unpinned, or with invalid validity timestamps). This is a local trust
			// configuration/update failure, not evidence that the root is bogus (R-039).
			result.Status = StatusIndeterminate
			result.AddError("no currently-active pinned root trust anchor available (check anchor validity dates / refresh the anchor set); cannot establish trust")
			return result, nil
		}
		trust = func(keys []dnspkg.DNSKEYRecord) (*ChainLink, []dnspkg.DNSKEYRecord, error) {
			link, err := VerifyRootTrustAnchor(keys, activeAnchors)
			if err != nil {
				return nil, nil, fmt.Errorf("root trust anchor verification failed: %v", err)
			}
			return link, CollectAnchorMatchedKeys(keys, activeAnchors), nil
		}
	} else {
		// Non-root zone - verify DS from parent
		parentZone := parentZoneFromHierarchy(zone, hierarchy)
		ds, err := v.queryDSFromParentWithValidation(ctx, zone, parentZone, nsAddresses, parentDNSKEY)
		if err != nil {
			result.Status = StatusIndeterminate
			result.AddError(fmt.Sprintf("failed to query DS from parent: %v", err))
			return result, nil
		}
		result.Disagreements = append(result.Disagreements, ds.Disagreements...)

		// Store DS validation result
		if ds.Validation != nil {
			result.DSValidation = ds.Validation
		}

		if len(ds.Observed) == 0 {
			// No DS: insecure delegation only if the parent authenticatedly proves the
			// DS RRset is absent (R-081 downgrade guard).
			v.finalizeNoDSDelegation(result, zone, parentZone, parentDNSKEY, ds.Response)
			if result.Status == StatusInsecure {
				markUsable(StatusInsecure, "")
			}
			return result, nil
		}

		// The served (Answer-section, child-owned) DS RRset is recorded for
		// diagnostics; only the authenticated RRset below enters the chain.
		result.DS = ds.Observed

		// R-079: a secure delegation requires the DS RRset to be signed by the parent's
		// authenticated DNSKEY. Without a verified DS RRSIG, a forged DS pointing at an
		// attacker-generated key would be accepted. Fail closed to bogus.
		if ds.Validation == nil || !ds.Validation.RRSIGVerified || len(ds.Authenticated) == 0 {
			result.Status = StatusBogus
			msg := "DS RRset is not signed by the parent (no verified DS RRSIG)"
			if ds.Validation != nil && ds.Validation.Error != "" {
				msg = fmt.Sprintf("DS RRSIG verification failed: %s", ds.Validation.Error)
			}
			result.AddError(msg)
			return result, nil
		}

		// RA6X-017: classify the AUTHENTICATED DS RRset by supported algorithm and
		// digest type before matching (RFC 4035 §5.2, RFC 6840 §5.2). A DS this
		// validator cannot act on is not an authentication path; if none is
		// supported the delegation is treated as unsigned (insecure), not bogus.
		// This classification runs only after the parent authenticated the RRset,
		// so an injected unknown-algorithm DS can never downgrade a signed zone.
		supportedDS, unsupportedDS := SupportedDSRecords(ds.Authenticated)
		for _, d := range unsupportedDS {
			result.Warnings = append(result.Warnings, fmt.Sprintf(
				"parent DS (key tag %d, algorithm %d, digest type %d) uses an algorithm or digest type this validator does not support; it cannot serve as an authentication path",
				d.KeyTag, d.Algorithm, d.DigestType))
		}
		if len(supportedDS) == 0 {
			result.Status = StatusInsecure
			result.Warnings = append(result.Warnings,
				"the authenticated DS RRset contains only unsupported algorithms/digest types: no supported authentication path, so the zone is treated as unsigned (RFC 4035 §5.2 / RFC 6840 §5.2)")
			markUsable(StatusInsecure, "")
			result.QueryTimeNs = time.Since(start).Nanoseconds()
			return result, nil
		}

		trust = func(keys []dnspkg.DNSKEYRecord) (*ChainLink, []dnspkg.DNSKEYRecord, error) {
			// Validate DS matches DNSKEY (digest) and record the chain link, using
			// ONLY the exact DS RRset the parent's signature authenticated (RA6X-007)
			// and this validator can act on (RA6X-017).
			link, err := ValidateChainLink(supportedDS, keys, zone)
			if err != nil {
				return nil, nil, fmt.Errorf("chain of trust validation failed: %v", err)
			}
			// R-080: the DNSKEY RRset must be signed by a key the DS actually authenticates.
			return link, CollectDSMatchedKeys(supportedDS, keys, zone), nil
		}

		// Query RDAP for out-of-band DS verification (only for registrable domains)
		if v.rdapClient != nil && IsRegistrableDomain(zone) {
			rdapResult := v.queryRDAPSecureDNS(ctx, zone, ds.Authenticated)
			result.RDAPSecureDNS = rdapResult
			if rdapResult != nil && rdapResult.DSMatch == DSMatchNone {
				result.Warnings = append(result.Warnings, "RDAP DS records do not match DNS DS records")
			}
		}
	}

	// Authenticate the zone from the first server response whose DNSKEY RRset
	// chains to the trust source: DS/anchor digest match AND an RRSIG over the
	// exact wire RRset (Answer section, owned by the zone — RA6X-007) by an
	// authenticated key (RFC 4035 §5.2, R-080). One valid path suffices; the
	// other servers are then judged against it rather than being required to
	// agree beforehand (RA6X-018).
	var authenticatedKeys []dnspkg.DNSKEYRecord
	chosen := -1
	var firstErr error
	for _, i := range withKeys {
		sr := &serverResults[i]
		keys := answerDNSKEYsOwnedBy(sr.Response.DNSKEY, zone)
		link, authed, err := trust(keys)
		if err == nil {
			if len(sr.Response.RawResponse) == 0 {
				err = fmt.Errorf("DNSKEY response could not be retained in wire form; cannot verify the DNSKEY RRset")
			} else if _, verr := VerifyDNSKEYRRsetFromResponse(sr.Response.RawResponse, zone, authed); verr != nil {
				err = fmt.Errorf("DNSKEY RRSIG verification failed: %v", verr)
			}
		}
		if err != nil {
			sr.Status = StatusBogus
			sr.Error = err.Error()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		chosen = i
		result.ChainLink = link
		authenticatedKeys = authed
		result.DNSKEY = keys
		result.RRSIG = sr.Response.RRSIG
		result.NSEC = sr.Response.NSEC
		result.NSEC3 = sr.Response.NSEC3
		break
	}
	if chosen < 0 {
		result.Status = StatusBogus
		result.AddError(firstErr.Error())
		for _, i := range usable {
			if serverResults[i].Status == StatusValidating {
				serverResults[i].Status = StatusBogus
				serverResults[i].Error = "served no DNSKEY RRset while other servers did"
			}
		}
		applyServerResults()
		return result, nil
	}

	// Judge every queried server against the authenticated chain (RA6X-018).
	v.judgeDNSKEYServers(result, serverResults, zone, result.DNSKEY, authenticatedKeys)
	applyServerResults()

	// RFC 4034 §3.1.3: Detect wildcard synthesis (informational)
	if rrsig := FindRRSIGForType(dns.TypeDNSKEY, result.RRSIG); rrsig != nil {
		if wildcard := DetectWildcardSynthesis(zone, *rrsig); wildcard != "" {
			result.WildcardSource = wildcard
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Response synthesized from wildcard %s", wildcard))
		}
	}

	// Check for RFC compliance warnings (informational, don't affect status)

	// RFC 8624: Deprecated algorithm warnings
	result.Warnings = append(result.Warnings, CheckAlgorithmDeprecation(result.DNSKEY)...)
	result.Warnings = append(result.Warnings, CheckRRSIGAlgorithmDeprecation(result.RRSIG)...)
	result.Warnings = append(result.Warnings, CheckDigestTypeDeprecation(result.DS)...)

	// RFC 9276: NSEC3 iteration count warnings
	result.Warnings = append(result.Warnings, CheckNSEC3Iterations(result.NSEC3)...)

	// RFC 5155: NSEC3 opt-out status (informational)
	if optOut, explanation := CheckNSEC3OptOut(result.NSEC3); optOut {
		result.NSEC3OptOut = true
		result.Warnings = append(result.Warnings, explanation)
	}

	result.Status = StatusSecure
	result.QueryTimeNs = time.Since(start).Nanoseconds()

	return result, nil
}

// parentDSResult is what the parent zone said about a delegation's DS RRset,
// split into what was served and what was actually authenticated (RA6X-007).
type parentDSResult struct {
	// Observed is the DS RRset the parent served in its Answer section for the
	// child owner. It is diagnostic data: present means "the parent claims a
	// signed delegation", but nothing here is authenticated.
	Observed []dnspkg.DSRecord
	// Authenticated is the exact DS RRset whose RRSIG verified under the
	// parent's authenticated DNSKEYs, or nil. Only this set may match child
	// keys or build the chain link.
	Authenticated []dnspkg.DSRecord
	Validation    *DSValidation
	// Response is the parent's raw query result, kept so the caller can inspect
	// the authenticated denial (NSEC/NSEC3) when the DS RRset is absent (R-081).
	Response *dnspkg.QueryResult
	// Disagreements records parent servers whose DS answer differed from, or
	// failed to authenticate against, the one used (extended mode, RA6X-018).
	Disagreements []Disagreement
}

// parentZoneFromHierarchy returns the zone that precedes zone in the walked
// hierarchy: the actual parent whose servers hold the DS RRset and whose keys
// sign it. A delegation whose parent skips labels (child.branch.example.
// delegated directly from example.) has that parent, not the name one label
// up. It falls back to dropping one label when zone is not in the hierarchy.
func parentZoneFromHierarchy(zone string, hierarchy []string) string {
	want := canonicalizeName(zone)
	for i, z := range hierarchy {
		if canonicalizeName(z) != want {
			continue
		}
		if i == 0 {
			return ""
		}
		return canonicalizeName(hierarchy[i-1])
	}
	return GetParentZone(zone)
}

// queryDSFromParentWithValidation queries DS records from the parent's servers
// and verifies the DS RRSIG under the parent's authenticated keys. The result
// separates the served DS RRset from the exact authenticated one, and carries
// the raw parent response for DS-absence proofs (R-081).
func (v *Validator) queryDSFromParentWithValidation(ctx context.Context, zone, parentZone string, fallbackServers []string, parentDNSKEY []dnspkg.DNSKEYRecord) (*parentDSResult, error) {
	validation := &DSValidation{
		ParentZone: parentZone,
	}

	// First try to get parent NS
	var parentNS []string
	if parentZone == "." {
		parentNS = v.rootServerAddresses()
	} else {
		nsRecords, err := v.resolver.ResolveNSWithAddresses(ctx, parentZone)
		if err == nil {
			for _, ns := range nsRecords {
				for _, addr := range ns.Addresses {
					parentNS = append(parentNS, addr.String())
				}
			}
		}
	}

	// Fall back to provided servers if no parent NS found
	if len(parentNS) == 0 {
		parentNS = fallbackServers
	}

	// Query DS from parent nameservers. The first usable answer establishes
	// the DS RRset; in extended mode the remaining parent servers are queried
	// too and judged against it (RA6X-018).
	var out *parentDSResult
	for idx, addr := range parentNS {
		result, err := v.resolver.QueryDSAuthoritative(ctx, addr, zone)
		if out != nil {
			// Extended mode: judge this parent server against the chosen answer.
			if d := judgeParentDSServer(out, addr, result, err, zone, parentZone, parentDNSKEY); d != nil {
				out.Disagreements = append(out.Disagreements, *d)
			}
			continue
		}
		if err == nil && result.Error == "" && result.RCode == 0 {
			out = &parentDSResult{
				Observed:   answerDSOwnedBy(result.DS, zone),
				Validation: validation,
				Response:   result,
			}
			validation.DSCount = len(out.Observed)

			// Verify DS RRSIG if we have parent's DNSKEY and a DS RRset was served.
			if len(parentDNSKEY) > 0 && len(out.Observed) > 0 {
				out.Authenticated = verifyDSRRSIGSet(validation, zone, parentZone, parentDNSKEY, result.RawResponse)
			}
			if v.quickMode || idx == len(parentNS)-1 {
				return out, nil
			}
			continue
		}
		// NXDOMAIN or no DS records
		if result != nil && result.RCode == dns.RcodeNameError {
			return &parentDSResult{Validation: validation, Response: result}, nil // Zone doesn't exist in parent
		}
	}
	if out != nil {
		return out, nil
	}

	return nil, fmt.Errorf("failed to query DS from parent zone")
}

// judgeParentDSServer compares one additional parent server's DS answer with
// the chosen one (RA6X-018): it must answer, serve the same DS RRset for the
// child, and (when the parent's keys are known) its signature must verify.
func judgeParentDSServer(chosen *parentDSResult, addr string, qr *dnspkg.QueryResult, err error, zone, parentZone string, parentDNSKEY []dnspkg.DNSKEYRecord) *Disagreement {
	d := &Disagreement{Server: "parent " + parentZone, IP: addr}
	switch {
	case err != nil:
		d.Issue, d.Expected, d.Got = "parent server did not answer the DS query", "DS answer", err.Error()
		return d
	case qr == nil || qr.Error != "":
		d.Issue, d.Expected = "parent server did not answer the DS query", "DS answer"
		if qr != nil {
			d.Got = qr.Error
		}
		return d
	case qr.RCode != dns.RcodeSuccess:
		d.Issue, d.Expected, d.Got = "parent server answered the DS query with an error", "NOERROR", qr.RCodeName
		return d
	}
	observed := answerDSOwnedBy(qr.DS, zone)
	if !sameDSRecords(observed, chosen.Observed) {
		d.Issue, d.Expected, d.Got = "parent server served a different DS RRset", dsSummary(chosen.Observed), dsSummary(observed)
		return d
	}
	if len(parentDNSKEY) > 0 && len(observed) > 0 {
		v := &DSValidation{ParentZone: parentZone}
		if got := verifyDSRRSIGSet(v, zone, parentZone, parentDNSKEY, qr.RawResponse); got == nil {
			d.Issue, d.Expected, d.Got = "parent server's DS RRSIG does not verify", "valid signature", v.Error
			return d
		}
	}
	return nil
}

// sameDSRecords reports whether two DS sets hold the same records.
func sameDSRecords(a, b []dnspkg.DSRecord) bool {
	key := func(d dnspkg.DSRecord) string {
		return fmt.Sprintf("%d/%d/%d/%s", d.KeyTag, d.Algorithm, d.DigestType, strings.ToUpper(d.Digest))
	}
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, d := range a {
		set[key(d)] = true
	}
	for _, d := range b {
		if !set[key(d)] {
			return false
		}
	}
	return true
}

// dsSummary describes a DS set briefly for a disagreement message.
func dsSummary(ds []dnspkg.DSRecord) string {
	if len(ds) == 0 {
		return "no DS"
	}
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		parts = append(parts, fmt.Sprintf("%d/%d/%d", d.KeyTag, d.Algorithm, d.DigestType))
	}
	return fmt.Sprintf("%d DS (%s)", len(ds), strings.Join(parts, ","))
}

// verifyDSRRSIGSet verifies the DS RRset for childZone in the parent's raw
// response against the parent's authenticated DNSKEYs and records the outcome
// on validation. It returns the exact DS RRset that was authenticated, or nil.
//
// Per RFC 4035 §5.3.3 the RRset is authenticated if ANY covering RRSIG
// verifies — a parent mid-rollover (double-signature) legitimately serves
// several — so every covering RRSIG is tried as an indivisible candidate. The
// RRset must be owned by the child in the parent's Answer section (R-027) and
// signed by the parent zone (RA6X-007); a DS replayed for another delegation
// or injected in Authority/Additional never verifies and is never returned.
func verifyDSRRSIGSet(validation *DSValidation, childZone, parentZone string, parentDNSKEY []dnspkg.DNSKEYRecord, rawResponse []byte) []dnspkg.DSRecord {
	verified, err := VerifyRRsetFromResponse(rawResponse, dns.TypeDS, parentDNSKEY, childZone, parentZone, true)
	if err != nil {
		validation.Error = fmt.Sprintf("DS RRSIG verification failed: %v", err)
		return nil
	}
	validation.RRSIGVerified = true
	validation.ParentSigningKey = verified.Signature.KeyTag
	return dsRecordsFromVerified(verified)
}

// verifyDSAbsence checks that the parent zone (parentZone, whose authenticated keys
// are parentDNSKEY) authenticatedly denies the existence of a DS RRset at childName
// (RFC 4035 §5.2, RFC 5155 §6 / §7.2.4). It returns the proof and whether it is
// cryptographically verified. Denial records must be owned within and signed by
// parentZone (RA6X-016). This is what distinguishes a genuine insecure
// delegation from a DS-stripping downgrade attack: an on-path attacker can remove the DS
// RRset from a response, but cannot forge the parent's signed NSEC/NSEC3 denial.
func (v *Validator) verifyDSAbsence(childName, parentZone string, parentDNSKEY []dnspkg.DNSKEYRecord, qr *dnspkg.QueryResult) (*NSECProof, bool) {
	if qr == nil {
		return &NSECProof{ResponseType: "DS-ABSENCE", Error: "no parent response available to prove DS absence"}, false
	}
	child := canonicalizeName(childName)

	// Only Answer/Authority records are denial candidates, and only records
	// whose RRset signature verified under the parent's keys may prove
	// anything (RA6X-007): the semantic checks below run on the authenticated
	// set, never on the served display slice.
	nsecCands := denialNSECCandidates(qr.NSEC)
	nsec3Cands := denialNSEC3Candidates(qr.NSEC3)

	if len(nsecCands) > 0 {
		proof := &NSECProof{ProofType: "NSEC", ResponseType: "DS-ABSENCE", Records: make([]string, 0)}
		for _, nsec := range nsecCands {
			proof.Records = append(proof.Records, fmt.Sprintf("%s types: %v", nsec.Owner, nsec.TypeBitmap))
		}
		verified, rejected, err := VerifyDenialRRsetsFromResponse(qr.RawResponse, dns.TypeNSEC, parentDNSKEY, parentZone)
		if err != nil {
			proof.Error = fmt.Sprintf("NSEC RRSIG verification failed: %v", err)
			return proof, false
		}
		matched := false
		for _, nsec := range nsecRecordsFromVerified(verified) {
			if canonicalizeName(nsec.Owner) != child {
				continue
			}
			if HasTypeInBitmap("DS", nsec.TypeBitmap) {
				proof.Error = "parent NSEC at the delegation point has the DS bit set"
				return proof, false
			}
			// A delegation NSEC has the NS bit set and the SOA bit clear (RFC 6840 §4.4);
			// this confirms it is a delegation point, not the apex or an empty non-terminal.
			if !HasTypeInBitmap("NS", nsec.TypeBitmap) || HasTypeInBitmap("SOA", nsec.TypeBitmap) {
				continue
			}
			matched = true
			proof.CoveringNSEC = fmt.Sprintf("%s types: %v", nsec.Owner, nsec.TypeBitmap)
			break
		}
		if !matched {
			proof.Error = fmt.Sprintf("no authenticated NSEC at %s proves the DS RRset is absent%s", child, rejectedNote(rejected))
			return proof, false
		}
		proof.Verified = true
		proof.Explanation = fmt.Sprintf("Authenticated NSEC proves no DS at %s (insecure delegation)", child)
		return proof, true
	}

	if len(nsec3Cands) > 0 {
		proof := &NSECProof{ProofType: "NSEC3", ResponseType: "DS-ABSENCE", Records: make([]string, 0)}
		// RFC 9276: refuse excessive iteration counts before any hashing (R-088).
		// Failing the proof here keeps this fail-closed: an over-cap NSEC3 can
		// never be used to prove an insecure delegation.
		if iters, over := nsec3IterationsOverCap(nsec3Cands); over {
			proof.Error = fmt.Sprintf("NSEC3 iterations=%d exceeds RFC 9276 cap of %d; refusing (CPU-amplification DoS vector)", iters, NSEC3MaxRecommendedIterations)
			return proof, false
		}
		for _, rec := range nsec3Cands {
			proof.Records = append(proof.Records, fmt.Sprintf("%s → %s types: %v", rec.HashedOwner, rec.NextHashed, rec.TypeBitmap))
		}
		verified, rejected, err := VerifyDenialRRsetsFromResponse(qr.RawResponse, dns.TypeNSEC3, parentDNSKEY, parentZone)
		if err != nil {
			proof.Error = fmt.Sprintf("NSEC3 RRSIG verification failed: %v", err)
			return proof, false
		}
		// RA6X-013: every proof lives inside one parameter-consistent chain; a
		// hash computed with one chain's salt is never compared with another
		// chain's intervals. RA6X-012: records with unknown flags are ignored.
		chains, ignored, err := nsec3Chains(nsec3RecordsFromVerified(verified))
		if err != nil {
			proof.Error = fmt.Sprintf("no usable NSEC3 chain: %v", err)
			return proof, false
		}
		proof.Ignored = ignored
		lastErr := ""
		for _, chain := range chains {
			childHash := chain.hash(child)
			// 1) Direct match: an NSEC3 whose owner hash equals H(child) with the DS bit
			//    clear and the NS bit set is the delegation-point NSEC3 (non-opt-out zones).
			if rec := chain.match(childHash); rec != nil {
				if HasTypeInBitmap("DS", rec.TypeBitmap) {
					proof.Error = "parent NSEC3 at the delegation point has the DS bit set"
					return proof, false
				}
				if !HasTypeInBitmap("NS", rec.TypeBitmap) || HasTypeInBitmap("SOA", rec.TypeBitmap) {
					lastErr = fmt.Sprintf("NSEC3 matching %s is not a delegation point (NS clear or SOA set); it does not prove an insecure delegation", child)
					continue
				}
				proof.Verified = true
				proof.ClosestEncloser = child
				proof.CoveringNSEC = fmt.Sprintf("NSEC3 %s types: %v", rec.HashedOwner, rec.TypeBitmap)
				proof.Explanation = fmt.Sprintf("Authenticated NSEC3 matches %s with the DS bit clear (insecure delegation)", child)
				return proof, true
			}
			// 2) Opt-out: an unsigned delegation without its own NSEC3 is proven by a
			//    COMPLETE closest-encloser proof (RFC 5155 §8.3) in which the next
			//    closer name is covered by an opt-out NSEC3 (RFC 5155 §6, §8.9). A
			//    cover alone, or a non-opt-out cover, proves nothing about a
			//    delegation (RA6X-012).
			ce, nextCloser, _, ncRec, err := chain.closestEncloser(child)
			if err != nil {
				lastErr = err.Error()
				continue
			}
			if !isOptOut(ncRec) {
				lastErr = fmt.Sprintf("next closer name %s of %s is covered by a non-opt-out NSEC3: the name does not exist in the parent, so this is not an unsigned delegation", nextCloser, child)
				continue
			}
			proof.Verified = true
			proof.OptOut = true
			proof.ClosestEncloser = ce
			proof.NextCloser = nextCloser
			proof.CoveringNSEC = fmt.Sprintf("NSEC3 %s -> %s [opt-out]", ncRec.HashedOwner, ncRec.NextHashed)
			proof.Explanation = fmt.Sprintf("Authenticated opt-out NSEC3 covers the next closer name %s below closest encloser %s (unsigned delegation permitted by opt-out; insecure)", nextCloser, ce)
			return proof, true
		}
		if lastErr == "" {
			lastErr = fmt.Sprintf("no authenticated NSEC3 proves the DS RRset is absent for %s", child)
		}
		proof.Error = lastErr + rejectedNote(rejected)
		return proof, false
	}

	return &NSECProof{ResponseType: "DS-ABSENCE", Error: "no NSEC/NSEC3 records accompany the DS-absent response"}, false
}

// rejectedNote formats the unverifiable denial RRsets a proof had to ignore,
// for inclusion in a failure message; empty when nothing was rejected.
func rejectedNote(rejected []string) string {
	if len(rejected) == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d unverifiable denial RRset(s) ignored: %s)", len(rejected), strings.Join(rejected, "; "))
}

// finalizeNoDSDelegation sets result.Status for a zone whose parent returned no DS record.
// When the parent is secure (we hold its authenticated DNSKEY), declaring the zone
// "insecure" requires an authenticated proof that the DS RRset is genuinely absent
// (R-081). Without such a proof the result is indeterminate (no denial at all) or bogus
// (a denial that contradicts itself or fails to verify) — never a silent downgrade.
func (v *Validator) finalizeNoDSDelegation(result *ZoneResult, zone, parentZone string, parentDNSKEY []dnspkg.DNSKEYRecord, qr *dnspkg.QueryResult) {
	if len(parentDNSKEY) == 0 {
		// The parent is not itself secured (insecure ancestor); there is no chain of
		// trust to protect below it, so an unsigned delegation is genuinely insecure.
		result.Status = StatusInsecure
		return
	}

	proof, ok := v.verifyDSAbsence(zone, parentZone, parentDNSKEY, qr)
	if proof != nil {
		result.DenialProof = proof
	}
	if ok {
		result.Status = StatusInsecure
		return
	}

	if qr == nil || (len(qr.NSEC) == 0 && len(qr.NSEC3) == 0) {
		// No authenticated denial available at all: we cannot prove insecure, and a
		// stripped DS would look identical. Fail to indeterminate rather than downgrade.
		result.Status = StatusIndeterminate
		result.AddError("insecure delegation claimed but the parent returned no authenticated proof of DS absence (possible downgrade attack)")
		return
	}

	result.Status = StatusBogus
	errMsg := "the parent's proof of DS absence did not verify (possible downgrade attack)"
	if proof != nil && proof.Error != "" {
		errMsg = fmt.Sprintf("the parent's proof of DS absence did not verify: %s", proof.Error)
	}
	result.AddError(errMsg)
}

// ValidateMultipleServers queries the zone's DNSKEY from all servers in
// parallel and records each server's REACHABILITY: a NOERROR answer is
// StatusValidating (queried, not yet judged) with its response attached; a
// transport failure or failure RCODE is StatusIndeterminate. Nothing here is
// an authentication verdict — judgeDNSKEYServers assigns those once the zone's
// chain is established (RA6X-018). In quick mode, only the first two servers
// are queried for speed.
func (v *Validator) ValidateMultipleServers(ctx context.Context, zone string, servers []string) []AddressResult {
	// In quick mode, limit to first 2 servers (primary + one fallback)
	queryServers := servers
	if v.quickMode && len(servers) > 2 {
		queryServers = servers[:2]
	}

	results := make([]AddressResult, len(queryServers))
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Limit concurrency
	semaphore := make(chan struct{}, v.maxConcurrent)

	for i, server := range queryServers {
		wg.Add(1)
		go func(idx int, srv string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			queryResult, _ := v.resolver.QueryDNSKEYAuthoritative(ctx, srv, zone)
			result := AddressResult{
				IP:     srv,
				Status: StatusValidating,
			}

			if queryResult == nil {
				result.Status = StatusIndeterminate
				result.Error = "query failed"
			} else if queryResult.Error != "" {
				result.Status = StatusIndeterminate
				result.Error = queryResult.Error
			} else if queryResult.RCode != 0 {
				result.Status = StatusIndeterminate
				result.Error = queryResult.RCodeName
			} else {
				result.RTTNs = queryResult.RTT.Nanoseconds()
				result.Response = queryResult
			}

			mu.Lock()
			results[idx] = result
			mu.Unlock()
		}(i, server)
	}

	wg.Wait()
	return results
}

// dnskeyMaterialSet returns the canonical identity of each key in keys
// (owner, flags, protocol, algorithm, public key) as a set. Key tags are a
// 16-bit hint that collides; consensus must compare the complete material
// (RA6X-018).
func dnskeyMaterialSet(keys []dnspkg.DNSKEYRecord) map[string]bool {
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[fmt.Sprintf("%s/%d/%d/%d/%s", dns.CanonicalName(k.Owner), k.Flags, k.Protocol, k.Algorithm, k.PublicKey)] = true
	}
	return set
}

// sameDNSKEYMaterial reports whether two DNSKEY sets hold exactly the same
// key material.
func sameDNSKEYMaterial(a, b []dnspkg.DNSKEYRecord) bool {
	sa, sb := dnskeyMaterialSet(a), dnskeyMaterialSet(b)
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}

// keyTagSummary describes a key set briefly for a disagreement message.
func keyTagSummary(keys []dnspkg.DNSKEYRecord) string {
	if len(keys) == 0 {
		return "no DNSKEY"
	}
	tags := make([]string, 0, len(keys))
	for _, k := range keys {
		tags = append(tags, fmt.Sprintf("%d", k.KeyTag))
	}
	return fmt.Sprintf("%d keys (tags %s)", len(keys), strings.Join(tags, ","))
}

// judgeDNSKEYServers assigns every queried server a per-server verdict against
// the authenticated chain (RA6X-018): its Answer-section DNSKEY RRset must
// hold exactly the authenticated key material and its RRSIG must verify under
// the authenticated keys. A server that answered but failed either check is
// bogus and recorded as a disagreement; a server that did not answer stays
// indeterminate. Disagreement is diagnostic: the zone's own verdict already
// rests on the one valid path that was found, and one dissenting server never
// changes it, but every dissent is visible per address and in Disagreements.
func (v *Validator) judgeDNSKEYServers(result *ZoneResult, serverResults []AddressResult, zone string, authenticatedRRset, authenticatedKeys []dnspkg.DNSKEYRecord) {
	for i := range serverResults {
		sr := &serverResults[i]
		if sr.Response == nil {
			continue
		}
		keys := answerDNSKEYsOwnedBy(sr.Response.DNSKEY, zone)
		if !sameDNSKEYMaterial(keys, authenticatedRRset) {
			sr.Status = StatusBogus
			if len(keys) == 0 {
				sr.Error = "served no DNSKEY RRset while the zone's authenticated DNSKEY RRset exists"
			} else {
				sr.Error = "served a DNSKEY RRset that differs from the authenticated RRset"
			}
			result.Disagreements = append(result.Disagreements, Disagreement{
				Server:   sr.IP,
				IP:       sr.IP,
				Issue:    "DNSKEY RRset differs from the authenticated RRset",
				Expected: keyTagSummary(authenticatedRRset),
				Got:      keyTagSummary(keys),
			})
			continue
		}
		if len(sr.Response.RawResponse) == 0 {
			sr.Status = StatusIndeterminate
			sr.Error = "DNSKEY response could not be retained in wire form"
			continue
		}
		if _, err := VerifyDNSKEYRRsetFromResponse(sr.Response.RawResponse, zone, authenticatedKeys); err != nil {
			sr.Status = StatusBogus
			sr.Error = fmt.Sprintf("DNSKEY RRSIG verification failed: %v", err)
			result.Disagreements = append(result.Disagreements, Disagreement{
				Server:   sr.IP,
				IP:       sr.IP,
				Issue:    "DNSKEY RRSIG does not verify under the authenticated keys",
				Expected: "valid signature",
				Got:      err.Error(),
			})
			continue
		}
		sr.Status = StatusSecure
		sr.Error = ""
	}
	for _, d := range result.Disagreements {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Nameserver %s: %s (expected %s, got %s)", d.IP, d.Issue, d.Expected, d.Got))
	}
}

// queryRDAPSecureDNS queries RDAP for secureDNS information and compares with DNS DS records
func (v *Validator) queryRDAPSecureDNS(ctx context.Context, zone string, dnsDS []dnspkg.DSRecord) *RDAPSecureDNS {
	if v.rdapClient == nil {
		return nil
	}

	result := &RDAPSecureDNS{
		DSMatch: DSMatchNoRDAP,
	}

	secureDNS, err := v.rdapClient.GetSecureDNS(ctx, zone)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	// Domain not found in RDAP
	if secureDNS == nil {
		result.Error = "domain not found in RDAP"
		return result
	}

	result.DelegationSigned = secureDNS.DelegationSigned

	// If RDAP says unsigned
	if !secureDNS.DelegationSigned || len(secureDNS.DSData) == 0 {
		result.DSMatch = DSMatchUnsigned
		// Warning if DNS has DS but RDAP says unsigned
		if len(dnsDS) > 0 {
			result.Error = "RDAP reports domain as unsigned but DNS has DS records"
		}
		return result
	}

	// Convert RDAP DS records to our format for comparison
	rdapDS := make([]dnspkg.DSRecord, 0, len(secureDNS.DSData))
	for _, ds := range secureDNS.DSData {
		rdapDS = append(rdapDS, dnspkg.DSRecord{
			KeyTag:     uint16(ds.KeyTag),
			Algorithm:  uint8(ds.Algorithm),
			DigestType: uint8(ds.DigestType),
			Digest:     strings.ToUpper(ds.Digest),
		})
	}
	result.DSData = rdapDS

	// Compare DS records
	result.DSMatch = compareDSRecords(dnsDS, rdapDS)

	return result
}

// compareDSRecords compares DNS and RDAP DS records
func compareDSRecords(dnsDS, rdapDS []dnspkg.DSRecord) DSMatchResult {
	if len(dnsDS) == 0 || len(rdapDS) == 0 {
		return DSMatchNone
	}

	// Normalize DNS DS digests to uppercase for comparison
	normalizedDNS := make(map[string]bool)
	for _, ds := range dnsDS {
		key := fmt.Sprintf("%d-%d-%d-%s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
		normalizedDNS[key] = true
	}

	matchCount := 0
	for _, ds := range rdapDS {
		key := fmt.Sprintf("%d-%d-%d-%s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToUpper(ds.Digest))
		if normalizedDNS[key] {
			matchCount++
		}
	}

	if matchCount == 0 {
		return DSMatchNone
	}
	if matchCount == len(rdapDS) && matchCount == len(dnsDS) {
		return DSMatchFull
	}
	return DSMatchPartial
}
