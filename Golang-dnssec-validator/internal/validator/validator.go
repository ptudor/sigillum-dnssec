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
				v.emitEvent("complete", CompleteEvent{
					Result:      result.Result,
					Chain:       result.Chain,
					CNAMEChains: result.CNAMEChains,
					DurationMs:  result.DurationMs,
					Errors:      result.Errors,
					Warnings:    result.Warnings,
				})
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
		})

		// Track overall status
		switch zoneResult.Status {
		case StatusBogus:
			lastStatus = StatusBogus
			// Stop validation on bogus
			result.Result = StatusBogus
			result.DurationMs = time.Since(start).Milliseconds()
			v.emitEvent("complete", CompleteEvent{
				Result:      result.Result,
				Chain:       result.Chain,
				CNAMEChains: result.CNAMEChains,
				DurationMs:  result.DurationMs,
				Errors:      result.Errors,
				Warnings:    result.Warnings,
			})
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

	// Verify actual record RRSIG at the leaf zone (only if chain is secure)
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
			// Update the cached result too
			if cached, ok := validatedZones[leafZone.Zone]; ok {
				cached.RecordValidation = recordValidation
				cached.Warnings = leafZone.Warnings
			}
			// R-082: fold the leaf record's signature outcome into the overall verdict. A
			// secure chain over an answer whose RRSIG is missing/expired/forged (and which
			// is not a verified denial) is not secure — the caller reads result.Result, so
			// the record failure must move the verdict, not just the per-zone detail.
			if verdict, msg := recordValidationVerdict(recordValidation); verdict != StatusSecure {
				lastStatus = verdict
				if msg != "" {
					result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", leafZone.Zone, msg))
				}
			}
		}
	}

	// Now check for CNAMEs at the target domain. checkAndFollowCNAME enforces the
	// loop/depth guards internally (R-034), so it is always consulted.
	{
		cnameResult, err := v.checkAndFollowCNAME(ctx, domain, depth, maxCNAMEDepth, visited, validatedZones)
		if err == nil && cnameResult != nil {
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
					result.Warnings = append(result.Warnings, fmt.Sprintf("CNAME target %s is indeterminate", cnameResult.Target))
				}
			}
		}
	}

	result.Result = lastStatus
	result.DurationMs = time.Since(start).Milliseconds()

	// Emit complete event (only for top-level)
	if depth == 0 {
		v.emitEvent("complete", CompleteEvent{
			Result:      result.Result,
			Chain:       result.Chain,
			CNAMEChains: result.CNAMEChains,
			DurationMs:  result.DurationMs,
			Errors:      result.Errors,
			Warnings:    result.Warnings,
		})
	}

	return result, nil
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

// checkAndFollowCNAME checks if the domain has a CNAME and validates the target.
// It carries the canonical-name visited set and enforces loop and depth limits
// (R-034): a repeated owner/target is a CNAME loop (bogus), and a chain that would
// exceed maxDepth without resolving is depth-limited (indeterminate) — neither is
// silently reported as secure.
func (v *Validator) checkAndFollowCNAME(ctx context.Context, domain string, depth, maxDepth int, visited map[string]bool, validatedZones map[string]*ZoneResult) (*CNAMEChainResult, error) {
	// Record this owner name so a later hop back to it is detected as a loop.
	visited[canonicalizeName(domain)] = true

	// First, find the authoritative zone for this domain
	// The zone is the closest ancestor that has NS records
	zones, err := v.resolver.DiscoverZoneCuts(ctx, domain)
	if err != nil || len(zones) == 0 {
		return nil, err
	}

	// The last zone in the list is the authoritative zone for this domain
	authZone := zones[len(zones)-1]

	// Get nameservers for the authoritative zone
	nsRecords, err := v.resolver.ResolveNSWithAddresses(ctx, authZone)
	if err != nil || len(nsRecords) == 0 {
		return nil, fmt.Errorf("no nameservers for zone %s", authZone)
	}

	// Collect NS addresses
	var nsAddresses []string
	for _, ns := range nsRecords {
		for _, addr := range ns.Addresses {
			nsAddresses = append(nsAddresses, addr.String())
		}
	}

	// Query the leaf record type from authoritative servers to check for CNAME.
	var queryResult *dnspkg.QueryResult
	for _, addr := range nsAddresses {
		result, err := v.resolver.QueryRecordAuthoritative(ctx, addr, domain, v.leafType())
		if err == nil && result.Error == "" {
			queryResult = result
			break
		}
	}

	if queryResult == nil {
		return nil, nil // Could not query authoritative servers
	}

	// Check for CNAME in the response
	if len(queryResult.CNAME) == 0 {
		return nil, nil // No CNAME, nothing to follow
	}

	// Found a CNAME
	cname := queryResult.CNAME[0]
	target := cname.Target

	// Emit CNAME event
	v.emitEvent("cname", CNAMEEvent{
		Source: domain,
		Target: target,
	})

	// R-034: stop on a CNAME loop (bogus) or depth-limit (indeterminate) rather than
	// looping to the cap and reading secure.
	if term, stop := cnameGuard(domain, target, depth, maxDepth, visited); stop {
		return term, nil
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
		}, nil
	}

	return &CNAMEChainResult{
		Source: domain,
		Target: target,
		Result: targetResult.Result,
		Chain:  targetResult.Chain,
	}, nil
}

// queryLeafAllServers queries the leaf record from the authoritative servers.
// In quick mode it returns the first usable answer. In extended mode it queries
// EVERY server, returns the first usable answer for the cryptographic
// verification, and reports any server whose answer disagrees with it — the
// "query every NS, flag inconsistencies" feature, previously applied only to the
// DNSKEY step (R-100).
func (v *Validator) queryLeafAllServers(ctx context.Context, nsAddresses []string, domain string) (*dnspkg.QueryResult, []string) {
	var first *dnspkg.QueryResult
	var firstFP string
	var disagreements []string

	for _, addr := range nsAddresses {
		select {
		case <-ctx.Done():
			return first, disagreements
		default:
		}
		result, err := v.resolver.QueryRecordAuthoritative(ctx, addr, domain, v.leafType())
		if err != nil || result == nil || result.Error != "" {
			continue
		}
		if first == nil {
			first = result
			firstFP = v.leafFingerprint(result)
			if v.quickMode {
				return first, nil
			}
			continue
		}
		if v.leafFingerprint(result) != firstFP {
			disagreements = append(disagreements, fmt.Sprintf(
				"%s (%s) returned a different %s answer (%s) than %s (%s) (%s)",
				result.Server, result.IP, v.leafTypeName(), result.RCodeName,
				first.Server, first.IP, first.RCodeName))
		}
	}
	return first, disagreements
}

// leafFingerprint builds a TTL-insensitive canonical summary of a server's
// answer for the leaf type (RCODE plus the sorted leaf/CNAME rdata), so answers
// can be compared across servers without flagging benign TTL differences.
func (v *Validator) leafFingerprint(qr *dnspkg.QueryResult) string {
	parts := []string{qr.RCodeName}
	if len(qr.RawResponse) > 0 {
		var msg dns.Msg
		if err := msg.Unpack(qr.RawResponse); err == nil {
			var rrs []string
			for _, rr := range msg.Answer {
				t := rr.Header().Rrtype
				if t != v.leafType() && t != dns.TypeCNAME {
					continue
				}
				h := rr.Header()
				saved := h.Ttl
				h.Ttl = 0
				rrs = append(rrs, strings.ToLower(rr.String()))
				h.Ttl = saved
			}
			sort.Strings(rrs)
			parts = append(parts, rrs...)
		}
	}
	return strings.Join(parts, "|")
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
	queryResult, disagreements := v.queryLeafAllServers(ctx, nsAddresses, domain)

	if queryResult == nil {
		return &RecordValidation{
			RecordType: v.leafTypeName(),
			Error:      fmt.Sprintf("failed to query %s record from authoritative servers", v.leafTypeName()),
		}
	}

	validation := &RecordValidation{
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
			proof := VerifyNSECDenialWithRRSIG(domain, v.leafType(), nsecCands, queryResult.RRSIG, dnskeys, queryResult.RawResponse, queryResult.RCode)
			validation.DenialProof = proof
			if proof.Verified {
				validation.RRSIGVerified = true
			} else if proof.Error != "" {
				validation.Error = proof.Error
			}
			return validation
		} else if len(nsec3Cands) > 0 {
			// Verify NSEC3 denial proof with full RRSIG verification
			proof := VerifyNSEC3DenialWithRRSIG(domain, v.leafType(), nsec3Cands, queryResult.RRSIG, dnskeys, zone, queryResult.RawResponse, queryResult.RCode)
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
	// owners are diagnostics, never candidates (RA6X-007).
	leafSigs := answerRRSIGsOwnedBy(queryResult.RRSIG, domain)
	leafCNAMEs := answerCNAMEsOwnedBy(queryResult.CNAME, domain)

	// Find RRSIG for the leaf record type
	rrsigA := FindRRSIGForType(v.leafType(), leafSigs)
	if rrsigA == nil {
		// Maybe it's a CNAME - check for CNAME RRSIG
		if len(leafCNAMEs) > 0 {
			rrsigCNAME := FindRRSIGForType(dns.TypeCNAME, leafSigs)
			if rrsigCNAME != nil {
				validation.RecordType = "CNAME"
				if !VerifyRRSIGValid(*rrsigCNAME) {
					if rrsigCNAME.IsExpired {
						validation.Error = fmt.Sprintf("CNAME RRSIG expired at %s", rrsigCNAME.Expiration.Format("2006-01-02T15:04:05Z"))
					} else {
						validation.Error = fmt.Sprintf("CNAME RRSIG not yet valid")
					}
					return validation
				}
				// Find signing-key candidates: every eligible key sharing the tag
				// (R-043 eligibility, R-044 collision-safe iteration).
				candidates := EligibleKeysByKeyTag(rrsigCNAME.KeyTag, dnskeys)
				switch {
				case len(candidates) == 0:
					validation.Error = fmt.Sprintf("CNAME signing key (tag %d) not found", rrsigCNAME.KeyTag)
				case !leafSignerMatchesZone(rrsigCNAME.SignerName, zone):
					// Defense-in-depth: the signature must be by a key in THIS
					// zone, mirroring the A-record path's signer-name check (R-096).
					validation.Error = fmt.Sprintf("CNAME RRSIG signer %s does not match zone %s", rrsigCNAME.SignerName, zone)
				default:
					count, err := VerifyRRsetRRSIGFromResponseAnyKey(queryResult.RawResponse, dns.TypeCNAME, candidates, rrsigCNAME.KeyTag, domain, true)
					if err == nil {
						validation.RRSIGVerified = true
						validation.SigningKeyTag = rrsigCNAME.KeyTag
						validation.RecordCount = count
						v.verifyWildcard(validation, domain, *rrsigCNAME, queryResult, dnskeys)
					} else {
						validation.Error = fmt.Sprintf("CNAME RRSIG cryptographic verification failed: %v", err)
					}
				}
				return validation
			}
		}
		validation.Error = "no RRSIG for A record"
		return validation
	}

	// Verify RRSIG time validity
	if !VerifyRRSIGValid(*rrsigA) {
		if rrsigA.IsExpired {
			validation.Error = fmt.Sprintf("A record RRSIG expired at %s", rrsigA.Expiration.Format("2006-01-02T15:04:05Z"))
		} else {
			validation.Error = fmt.Sprintf("A record RRSIG not yet valid")
		}
		return validation
	}

	// Find signing-key candidates: every eligible key sharing the tag
	// (R-043 eligibility, R-044 collision-safe iteration).
	candidates := EligibleKeysByKeyTag(rrsigA.KeyTag, dnskeys)
	if len(candidates) == 0 {
		validation.Error = fmt.Sprintf("A record signing key (tag %d) not found in zone DNSKEY", rrsigA.KeyTag)
		return validation
	}

	if leafSignerMatchesZone(rrsigA.SignerName, zone) {
		count, err := VerifyRRsetRRSIGFromResponseAnyKey(queryResult.RawResponse, v.leafType(), candidates, rrsigA.KeyTag, domain, true)
		if err == nil {
			validation.RRSIGVerified = true
			validation.SigningKeyTag = rrsigA.KeyTag
			validation.RecordCount = count
			v.verifyWildcard(validation, domain, *rrsigA, queryResult, dnskeys)
		} else {
			validation.Error = fmt.Sprintf("A record RRSIG cryptographic verification failed: %v", err)
		}
	} else {
		validation.Error = fmt.Sprintf("RRSIG signer %s does not match zone %s", rrsigA.SignerName, zone)
	}

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
func (v *Validator) verifyWildcard(validation *RecordValidation, qname string, rrsig dnspkg.RRSIGRecord, queryResult *dnspkg.QueryResult, dnskeys []dnspkg.DNSKEYRecord) {
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
		verified, _, err := VerifyDenialRRsetsFromResponse(queryResult.RawResponse, dns.TypeNSEC, dnskeys, "")
		if err != nil {
			cryptoErr = err
		} else {
			authNSEC = nsecRecordsFromVerified(verified)
		}
	case len(nsec3Cands) > 0:
		verified, _, err := VerifyDenialRRsetsFromResponse(queryResult.RawResponse, dns.TypeNSEC3, dnskeys, "")
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
		strings.HasPrefix(errText, "failed to query")
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

	serverResults, disagreements := v.ValidateMultipleServers(ctx, zone, nsAddresses)
	result.Disagreements = disagreements

	// Update nameserver results with per-server status
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

	// Find the first successful response
	var dnskeyResult *dnspkg.QueryResult
	for _, sr := range serverResults {
		if sr.Response != nil && sr.Status == StatusSecure {
			dnskeyResult = sr.Response
			break
		}
	}

	if dnskeyResult == nil {
		result.Status = StatusIndeterminate
		result.AddError("failed to query DNSKEY from any nameserver")
		return result, nil
	}

	// Report disagreements as warnings
	if len(disagreements) > 0 {
		for _, d := range disagreements {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Nameserver %s: %s (expected %s, got %s)", d.IP, d.Issue, d.Expected, d.Got))
		}
	}

	// Store DNSKEY records. The zone's DNSKEY RRset is the Answer-section set
	// owned by the zone; keys in other sections or at other owners are never
	// part of it (RA6X-007). The full parsed set with its section metadata
	// remains visible per server in Nameservers[].Addresses[].Response.
	result.DNSKEY = answerDNSKEYsOwnedBy(dnskeyResult.DNSKEY, zone)
	result.RRSIG = dnskeyResult.RRSIG
	result.NSEC = dnskeyResult.NSEC
	result.NSEC3 = dnskeyResult.NSEC3

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
		return result, nil
	}

	// Check if zone is signed
	if len(result.DNSKEY) == 0 {
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
			if len(ds.Observed) == 0 {
				// No DS in parent: insecure delegation only if the parent authenticatedly
				// proves the DS RRset is absent (R-081 downgrade guard).
				v.finalizeNoDSDelegation(result, zone, parentDNSKEY, ds.Response)
				return result, nil
			}
			// DS exists but no DNSKEY = bogus
			result.Status = StatusBogus
			result.AddError("DS exists in parent but zone has no DNSKEY")
			return result, nil
		}
		// Root without DNSKEY is bogus
		result.Status = StatusBogus
		result.AddError("root zone has no DNSKEY")
		return result, nil
	}

	// Establish the set of keys the parent authenticates for this zone. The DNSKEY RRset
	// MUST be signed by one of THESE keys (RFC 4035 §5.2), so DS/anchor authentication is
	// done first and its key identity is then required by the DNSKEY-RRSIG check below.
	var authenticatedKeys []dnspkg.DNSKEYRecord

	if zone == "." {
		// Root zone - verify DNSKEYs against the trust anchors (digest match).
		activeAnchors := dnspkg.GetActiveAnchors(v.anchors)
		if len(activeAnchors) == 0 {
			// No currently-active trust anchor (all future-dated, expired, or with
			// invalid validity timestamps). This is a local trust configuration/
			// update failure, not evidence that the root is bogus (R-039).
			result.Status = StatusIndeterminate
			result.AddError("no currently-active root trust anchor available (check anchor validity dates / refresh the anchor set); cannot establish trust")
			return result, nil
		}
		link, err := VerifyRootTrustAnchor(result.DNSKEY, activeAnchors)
		if err != nil {
			result.Status = StatusBogus
			result.AddError(fmt.Sprintf("root trust anchor verification failed: %v", err))
			return result, nil
		}
		result.ChainLink = link
		authenticatedKeys = CollectAnchorMatchedKeys(result.DNSKEY, activeAnchors)
	} else {
		// Non-root zone - verify DS from parent
		parentZone := parentZoneFromHierarchy(zone, hierarchy)
		ds, err := v.queryDSFromParentWithValidation(ctx, zone, parentZone, nsAddresses, parentDNSKEY)
		if err != nil {
			result.Status = StatusIndeterminate
			result.AddError(fmt.Sprintf("failed to query DS from parent: %v", err))
			return result, nil
		}

		// Store DS validation result
		if ds.Validation != nil {
			result.DSValidation = ds.Validation
		}

		if len(ds.Observed) == 0 {
			// No DS: insecure delegation only if the parent authenticatedly proves the
			// DS RRset is absent (R-081 downgrade guard).
			v.finalizeNoDSDelegation(result, zone, parentDNSKEY, ds.Response)
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

		// Validate DS matches DNSKEY (digest) and record the chain link, using
		// ONLY the exact DS RRset the parent's signature authenticated (RA6X-007).
		link, err := ValidateChainLink(ds.Authenticated, result.DNSKEY, zone)
		if err != nil {
			result.Status = StatusBogus
			result.AddError(fmt.Sprintf("chain of trust validation failed: %v", err))
			return result, nil
		}
		result.ChainLink = link

		// R-080: the DNSKEY RRset must be signed by a key the DS actually authenticates.
		authenticatedKeys = CollectDSMatchedKeys(ds.Authenticated, result.DNSKEY, zone)

		// Query RDAP for out-of-band DS verification (only for registrable domains)
		if v.rdapClient != nil && IsRegistrableDomain(zone) {
			rdapResult := v.queryRDAPSecureDNS(ctx, zone, ds.Authenticated)
			result.RDAPSecureDNS = rdapResult
			if rdapResult != nil && rdapResult.DSMatch == DSMatchNone {
				result.Warnings = append(result.Warnings, "RDAP DS records do not match DNS DS records")
			}
		}
	}

	// R-080: verify the DNSKEY RRset is signed by one of the parent/anchor-authenticated
	// keys — not merely by a key present in the RRset. This binds the DNSKEY RRset to the
	// parent's DS (RFC 4035 §5.2) and rejects a rogue self-signed KSK added to the RRset.
	// The verification runs over the exact wire RRset in the Answer section owned by
	// the zone, never over a reconstruction of the merged display slice (RA6X-007).
	if len(dnskeyResult.RawResponse) == 0 {
		result.Status = StatusIndeterminate
		result.AddError("DNSKEY response could not be retained in wire form; cannot verify the DNSKEY RRset")
		return result, nil
	}
	if _, err := VerifyDNSKEYRRsetFromResponse(dnskeyResult.RawResponse, zone, authenticatedKeys); err != nil {
		result.Status = StatusBogus
		result.AddError(fmt.Sprintf("DNSKEY RRSIG verification failed: %v", err))
		return result, nil
	}

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

	// Query DS from parent nameservers
	for _, addr := range parentNS {
		result, err := v.resolver.QueryDSAuthoritative(ctx, addr, zone)
		if err == nil && result.Error == "" && result.RCode == 0 {
			out := &parentDSResult{
				Observed:   answerDSOwnedBy(result.DS, zone),
				Validation: validation,
				Response:   result,
			}
			validation.DSCount = len(out.Observed)

			// Verify DS RRSIG if we have parent's DNSKEY and a DS RRset was served.
			if len(parentDNSKEY) > 0 && len(out.Observed) > 0 {
				out.Authenticated = verifyDSRRSIGSet(validation, zone, parentZone, parentDNSKEY, result.RawResponse)
			}

			return out, nil
		}
		// NXDOMAIN or no DS records
		if result != nil && result.RCode == dns.RcodeNameError {
			return &parentDSResult{Validation: validation, Response: result}, nil // Zone doesn't exist in parent
		}
	}

	return nil, fmt.Errorf("failed to query DS from parent zone")
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

// verifyDSAbsence checks that the parent authenticatedly denies the existence of a DS
// RRset at childName (RFC 4035 §5.2, RFC 5155 §6 / §7.2.4). It returns the proof and
// whether it is cryptographically verified. This is what distinguishes a genuine insecure
// delegation from a DS-stripping downgrade attack: an on-path attacker can remove the DS
// RRset from a response, but cannot forge the parent's signed NSEC/NSEC3 denial.
func (v *Validator) verifyDSAbsence(childName string, parentDNSKEY []dnspkg.DNSKEYRecord, qr *dnspkg.QueryResult) (*NSECProof, bool) {
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
		verified, rejected, err := VerifyDenialRRsetsFromResponse(qr.RawResponse, dns.TypeNSEC, parentDNSKEY, "")
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
		verified, rejected, err := VerifyDenialRRsetsFromResponse(qr.RawResponse, dns.TypeNSEC3, parentDNSKEY, "")
		if err != nil {
			proof.Error = fmt.Sprintf("NSEC3 RRSIG verification failed: %v", err)
			return proof, false
		}
		authenticated := nsec3RecordsFromVerified(verified)
		params := authenticated[0]
		if params.Algorithm != NSEC3HashSHA1 {
			proof.Error = fmt.Sprintf("unsupported NSEC3 hash algorithm: %d (only SHA-1 supported)", params.Algorithm)
			return proof, false
		}
		salt, err := hexDecode(params.Salt)
		if err != nil {
			proof.Error = fmt.Sprintf("invalid NSEC3 salt: %v", err)
			return proof, false
		}
		childHash := computeNSEC3Hash(child, salt, params.Iterations)
		// 1) Direct match: an NSEC3 whose owner hash equals H(child) with the DS bit clear
		//    and the NS bit set is the delegation-point NSEC3 (non-opt-out zones).
		for _, rec := range authenticated {
			if !strings.EqualFold(rec.HashedOwner, childHash) {
				continue
			}
			if HasTypeInBitmap("DS", rec.TypeBitmap) {
				proof.Error = "parent NSEC3 at the delegation point has the DS bit set"
				return proof, false
			}
			if !HasTypeInBitmap("NS", rec.TypeBitmap) {
				continue
			}
			proof.Verified = true
			proof.CoveringNSEC = fmt.Sprintf("NSEC3 %s types: %v", rec.HashedOwner, rec.TypeBitmap)
			proof.Explanation = fmt.Sprintf("Authenticated NSEC3 matches %s with the DS bit clear (insecure delegation)", child)
			return proof, true
		}
		// 2) Opt-out cover: an opt-out NSEC3 (Flags bit 0 set) whose hash range covers
		//    H(child) proves an unsigned delegation without its own NSEC3 (RFC 5155 §6).
		for _, rec := range authenticated {
			if rec.Flags&0x01 == 0 {
				continue
			}
			if hashBetween(childHash, rec.HashedOwner, rec.NextHashed) {
				proof.Verified = true
				proof.CoveringNSEC = fmt.Sprintf("NSEC3 %s -> %s [opt-out]", rec.HashedOwner, rec.NextHashed)
				proof.Explanation = fmt.Sprintf("Authenticated opt-out NSEC3 covers %s (insecure delegation)", child)
				return proof, true
			}
		}
		proof.Error = fmt.Sprintf("no authenticated NSEC3 proves the DS RRset is absent for %s%s", child, rejectedNote(rejected))
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
func (v *Validator) finalizeNoDSDelegation(result *ZoneResult, zone string, parentDNSKEY []dnspkg.DNSKEYRecord, qr *dnspkg.QueryResult) {
	if len(parentDNSKEY) == 0 {
		// The parent is not itself secured (insecure ancestor); there is no chain of
		// trust to protect below it, so an unsigned delegation is genuinely insecure.
		result.Status = StatusInsecure
		return
	}

	proof, ok := v.verifyDSAbsence(zone, parentDNSKEY, qr)
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

// ValidateMultipleServers queries all servers in parallel and checks for consensus.
// In quick mode, only the first two servers are queried for speed.
func (v *Validator) ValidateMultipleServers(ctx context.Context, zone string, servers []string) ([]AddressResult, []Disagreement) {
	// In quick mode, limit to first 2 servers (primary + one fallback)
	queryServers := servers
	if v.quickMode && len(servers) > 2 {
		queryServers = servers[:2]
	}

	results := make([]AddressResult, len(queryServers))
	var wg sync.WaitGroup
	var mu sync.Mutex
	disagreements := make([]Disagreement, 0)

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
				Status: StatusSecure,
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

	// Check for disagreements
	// Compare DNSKEY responses across servers
	var referenceKeys []dnspkg.DNSKEYRecord
	for _, r := range results {
		if r.Response != nil && len(r.Response.DNSKEY) > 0 {
			if referenceKeys == nil {
				referenceKeys = r.Response.DNSKEY
			} else {
				// Compare with reference
				if !compareDNSKEYSets(referenceKeys, r.Response.DNSKEY) {
					disagreements = append(disagreements, Disagreement{
						IP:       r.IP,
						Issue:    "DNSKEY mismatch",
						Expected: fmt.Sprintf("%d keys", len(referenceKeys)),
						Got:      fmt.Sprintf("%d keys", len(r.Response.DNSKEY)),
					})
				}
			}
		}
	}

	return results, disagreements
}

// compareDNSKEYSets compares two sets of DNSKEY records
func compareDNSKEYSets(a, b []dnspkg.DNSKEYRecord) bool {
	if len(a) != len(b) {
		return false
	}

	// Create map of key tags
	aKeys := make(map[uint16]bool)
	for _, k := range a {
		aKeys[k.KeyTag] = true
	}

	for _, k := range b {
		if !aKeys[k.KeyTag] {
			return false
		}
	}

	return true
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
