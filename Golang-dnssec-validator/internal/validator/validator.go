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
	return v.validateWithCache(ctx, domain, 0, make(map[string]*ZoneResult))
}

// ValidateWithDepth performs DNSSEC validation with CNAME recursion depth tracking
func (v *Validator) ValidateWithDepth(ctx context.Context, domain string, depth int) (*ValidationResult, error) {
	return v.validateWithCache(ctx, domain, depth, make(map[string]*ZoneResult))
}

// validateWithCache performs DNSSEC validation with a cache of already-validated zones
func (v *Validator) validateWithCache(ctx context.Context, domain string, depth int, validatedZones map[string]*ZoneResult) (*ValidationResult, error) {
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

		// Validate this zone (pass parent DNSKEY for DS RRSIG verification)
		zoneResult, err := v.validateZone(ctx, zone, zones, parentDNSKEY)
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

	// Now check for CNAMEs at the target domain
	if depth < maxCNAMEDepth {
		cnameResult, err := v.checkAndFollowCNAME(ctx, domain, depth, validatedZones)
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

// checkAndFollowCNAME checks if the domain has a CNAME and validates the target
func (v *Validator) checkAndFollowCNAME(ctx context.Context, domain string, depth int, validatedZones map[string]*ZoneResult) (*CNAMEChainResult, error) {
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

	v.emitEvent("progress", ProgressEvent{
		Zone:   target,
		Action: "following CNAME (reusing validated zones)",
	})

	// Validate the CNAME target, reusing already-validated zones
	targetResult, err := v.validateWithCache(ctx, target, depth+1, validatedZones)
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

	// Check for NXDOMAIN/NODATA with NSEC/NSEC3 proofs
	if isDenialForType(queryResult, v.leafType()) {
		// Check for denial proofs if this is NXDOMAIN or NODATA
		if len(queryResult.NSEC) > 0 {
			// Verify NSEC denial proof with full RRSIG verification
			proof := VerifyNSECDenialWithRRSIG(domain, v.leafType(), queryResult.NSEC, queryResult.RRSIG, dnskeys, queryResult.RawResponse, queryResult.RCode)
			validation.DenialProof = proof
			if proof.Verified {
				validation.RRSIGVerified = true
			} else if proof.Error != "" {
				validation.Error = proof.Error
			}
			return validation
		} else if len(queryResult.NSEC3) > 0 {
			// Verify NSEC3 denial proof with full RRSIG verification
			proof := VerifyNSEC3DenialWithRRSIG(domain, v.leafType(), queryResult.NSEC3, queryResult.RRSIG, dnskeys, zone, queryResult.RawResponse, queryResult.RCode)
			validation.DenialProof = proof
			if proof.Verified {
				validation.RRSIGVerified = true
			} else if proof.Error != "" {
				validation.Error = proof.Error
			}
			return validation
		}
	}

	// Find RRSIG for the leaf record type
	rrsigA := FindRRSIGForType(v.leafType(), queryResult.RRSIG)
	if rrsigA == nil {
		// Maybe it's a CNAME - check for CNAME RRSIG
		if len(queryResult.CNAME) > 0 {
			rrsigCNAME := FindRRSIGForType(dns.TypeCNAME, queryResult.RRSIG)
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
					count, err := VerifyRRsetRRSIGFromResponseAnyKey(queryResult.RawResponse, dns.TypeCNAME, candidates, rrsigCNAME.KeyTag)
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
		count, err := VerifyRRsetRRSIGFromResponseAnyKey(queryResult.RawResponse, v.leafType(), candidates, rrsigA.KeyTag)
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
	return signerName == zone || signerName == dns.Fqdn(zone)
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

	proof := VerifyWildcardDenial(qname, rrsig.Labels, queryResult.NSEC, queryResult.NSEC3)
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

	// The covering record exists; cryptographically verify its RRSIG(s).
	var cryptoErr error
	if len(queryResult.NSEC) > 0 {
		_, cryptoErr = VerifyDenialRRSIGFromResponse(queryResult.RawResponse, dns.TypeNSEC, dnskeys)
	} else {
		_, cryptoErr = VerifyDenialRRSIGFromResponse(queryResult.RawResponse, dns.TypeNSEC3, dnskeys)
	}
	if cryptoErr != nil {
		proof.Verified = false
		proof.Error = fmt.Sprintf("wildcard denial RRSIG cryptographic verification failed: %v", cryptoErr)
		if validation.Error == "" {
			validation.Error = fmt.Sprintf("wildcard answer from %s: %s", wildcard, proof.Error)
		}
		return
	}

	validation.WildcardProofVerified = true
}

// recordValidationVerdict classifies a leaf RecordValidation into the verdict it should
// contribute (R-082). A verified record signature or verified denial keeps the zone
// secure; an unqueryable answer is indeterminate; a missing/expired/forged signature or
// an unverifiable denial is bogus. A wildcard-synthesized answer whose record signature
// verified but whose closest-encloser proof is incomplete stays secure here — it is
// surfaced as a warning at the call site, matching the existing wildcard handling.
func recordValidationVerdict(rv *RecordValidation) (ValidationStatus, string) {
	if rv == nil || rv.RRSIGVerified {
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
func (v *Validator) validateZone(ctx context.Context, zone string, hierarchy []string, parentDNSKEY []dnspkg.DNSKEYRecord) (*ZoneResult, error) {
	result := NewZoneResult(zone)
	start := time.Now()

	// Get nameservers for this zone
	var nsAddresses []string
	if zone == "." {
		// Use root servers
		nsAddresses = dnspkg.GetRootServers()
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

	// Store DNSKEY records
	result.DNSKEY = dnskeyResult.DNSKEY
	result.RRSIG = dnskeyResult.RRSIG
	result.NSEC = dnskeyResult.NSEC
	result.NSEC3 = dnskeyResult.NSEC3

	// Check if zone is signed
	if len(result.DNSKEY) == 0 {
		// Zone might be insecure - check for DS in parent
		if zone != "." {
			parentZone := GetParentZone(zone)
			dsResult, _, dsQR, err := v.queryDSFromParentWithValidation(ctx, zone, parentZone, nsAddresses, parentDNSKEY)
			if err != nil {
				// A query failure is not evidence of an insecure delegation; do not
				// silently downgrade — report it as indeterminate.
				result.Status = StatusIndeterminate
				result.AddError(fmt.Sprintf("failed to query DS from parent: %v", err))
				return result, nil
			}
			if len(dsResult) == 0 {
				// No DS in parent: insecure delegation only if the parent authenticatedly
				// proves the DS RRset is absent (R-081 downgrade guard).
				v.finalizeNoDSDelegation(result, zone, parentDNSKEY, dsQR)
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
		parentZone := GetParentZone(zone)
		dsRecords, dsValidation, dsQR, err := v.queryDSFromParentWithValidation(ctx, zone, parentZone, nsAddresses, parentDNSKEY)
		if err != nil {
			result.Status = StatusIndeterminate
			result.AddError(fmt.Sprintf("failed to query DS from parent: %v", err))
			return result, nil
		}

		// Store DS validation result
		if dsValidation != nil {
			result.DSValidation = dsValidation
		}

		if len(dsRecords) == 0 {
			// No DS: insecure delegation only if the parent authenticatedly proves the
			// DS RRset is absent (R-081 downgrade guard).
			v.finalizeNoDSDelegation(result, zone, parentDNSKEY, dsQR)
			return result, nil
		}

		result.DS = dsRecords

		// R-079: a secure delegation requires the DS RRset to be signed by the parent's
		// authenticated DNSKEY. Without a verified DS RRSIG, a forged DS pointing at an
		// attacker-generated key would be accepted. Fail closed to bogus.
		if dsValidation == nil || !dsValidation.RRSIGVerified {
			result.Status = StatusBogus
			msg := "DS RRset is not signed by the parent (no verified DS RRSIG)"
			if dsValidation != nil && dsValidation.Error != "" {
				msg = fmt.Sprintf("DS RRSIG verification failed: %s", dsValidation.Error)
			}
			result.AddError(msg)
			return result, nil
		}

		// Validate DS matches DNSKEY (digest) and record the chain link.
		link, err := ValidateChainLink(dsRecords, result.DNSKEY, zone)
		if err != nil {
			result.Status = StatusBogus
			result.AddError(fmt.Sprintf("chain of trust validation failed: %v", err))
			return result, nil
		}
		result.ChainLink = link

		// R-080: the DNSKEY RRset must be signed by a key the DS actually authenticates.
		authenticatedKeys = CollectDSMatchedKeys(dsRecords, result.DNSKEY, zone)

		// Query RDAP for out-of-band DS verification (only for registrable domains)
		if v.rdapClient != nil && IsRegistrableDomain(zone) {
			rdapResult := v.queryRDAPSecureDNS(ctx, zone, dsRecords)
			result.RDAPSecureDNS = rdapResult
			if rdapResult != nil && rdapResult.DSMatch == DSMatchNone {
				result.Warnings = append(result.Warnings, "RDAP DS records do not match DNS DS records")
			}
		}
	}

	// R-080: verify the DNSKEY RRset is signed by one of the parent/anchor-authenticated
	// keys — not merely by a key present in the RRset. This binds the DNSKEY RRset to the
	// parent's DS (RFC 4035 §5.2) and rejects a rogue self-signed KSK added to the RRset.
	if err := VerifyDNSKEYRRSIGByKeys(result.DNSKEY, result.RRSIG, authenticatedKeys); err != nil {
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

// queryDSFromParentWithValidation queries DS records and verifies the DS RRSIG.
// It also returns the raw parent QueryResult so the caller can inspect the authenticated
// denial (NSEC/NSEC3) when the DS RRset is absent (R-081 downgrade protection).
func (v *Validator) queryDSFromParentWithValidation(ctx context.Context, zone, parentZone string, fallbackServers []string, parentDNSKEY []dnspkg.DNSKEYRecord) ([]dnspkg.DSRecord, *DSValidation, *dnspkg.QueryResult, error) {
	validation := &DSValidation{
		ParentZone: parentZone,
	}

	// First try to get parent NS
	var parentNS []string
	if parentZone == "." {
		parentNS = dnspkg.GetRootServers()
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
			validation.DSCount = len(result.DS)

			// Verify DS RRSIG if we have parent's DNSKEY
			if len(parentDNSKEY) > 0 && len(result.RRSIG) > 0 {
				verifyDSRRSIGSet(validation, result.RRSIG, parentDNSKEY, result.RawResponse)
			}

			return result.DS, validation, result, nil
		}
		// NXDOMAIN or no DS records
		if result != nil && result.RCode == dns.RcodeNameError {
			return nil, validation, result, nil // Zone doesn't exist in parent
		}
	}

	return nil, validation, nil, fmt.Errorf("failed to query DS from parent zone")
}

// verifyDSRRSIGSet verifies the DS RRset's covering RRSIGs against the parent's
// authenticated DNSKEYs and records the outcome on validation. Per RFC 4035
// §5.3.3 the RRset is authenticated if ANY covering RRSIG verifies — a parent
// mid-rollover (double-signature) legitimately serves several — so every
// covering RRSIG is tried before the verification is reported as failed.
func verifyDSRRSIGSet(validation *DSValidation, rrsigs []dnspkg.RRSIGRecord, parentDNSKEY []dnspkg.DNSKEYRecord, rawResponse []byte) {
	dsRRSIGs := FindRRSIGsForType(dns.TypeDS, rrsigs)
	if len(dsRRSIGs) == 0 {
		validation.Error = "no RRSIG for DS record"
		return
	}

	var errs []string
	for _, dsRRSIG := range dsRRSIGs {
		keyTag, err := verifyDSRRSIGOne(dsRRSIG, parentDNSKEY, rawResponse)
		if err == nil {
			validation.RRSIGVerified = true
			validation.ParentSigningKey = keyTag
			return
		}
		errs = append(errs, err.Error())
	}

	if len(errs) == 1 {
		validation.Error = errs[0]
		return
	}
	parts := make([]string, len(errs))
	for i, e := range errs {
		parts[i] = fmt.Sprintf("key tag %d: %s", dsRRSIGs[i].KeyTag, e)
	}
	validation.Error = fmt.Sprintf("none of %d RRSIGs over the DS RRset verified under the parent's DNSKEYs: %s", len(errs), strings.Join(parts, "; "))
}

// verifyDSRRSIGOne checks a single RRSIG over the DS RRset against the parent's
// authenticated DNSKEYs: signing-key lookup, time validity, and full
// cryptographic verification. It returns the signing key's tag on success.
func verifyDSRRSIGOne(dsRRSIG dnspkg.RRSIGRecord, parentDNSKEY []dnspkg.DNSKEYRecord, rawResponse []byte) (uint16, error) {
	// Every eligible parent key sharing the tag is a candidate (R-043/R-044).
	candidates := EligibleKeysByKeyTag(dsRRSIG.KeyTag, parentDNSKEY)
	if len(candidates) == 0 {
		return 0, fmt.Errorf("DS signing key (tag %d) not found in parent DNSKEY", dsRRSIG.KeyTag)
	}

	if !VerifyRRSIGValid(dsRRSIG) {
		if dsRRSIG.IsExpired {
			return 0, fmt.Errorf("DS RRSIG expired at %s", dsRRSIG.Expiration.Format("2006-01-02T15:04:05Z"))
		}
		return 0, fmt.Errorf("DS RRSIG not yet valid (inception: %s)", dsRRSIG.Inception.Format("2006-01-02T15:04:05Z"))
	}

	if _, err := VerifyRRsetRRSIGFromResponseAnyKey(rawResponse, dns.TypeDS, candidates, dsRRSIG.KeyTag); err != nil {
		return 0, fmt.Errorf("DS RRSIG cryptographic verification failed: %v", err)
	}

	return dsRRSIG.KeyTag, nil
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

	if len(qr.NSEC) > 0 {
		proof := &NSECProof{ProofType: "NSEC", ResponseType: "DS-ABSENCE", Records: make([]string, 0)}
		matched := false
		for _, nsec := range qr.NSEC {
			proof.Records = append(proof.Records, fmt.Sprintf("%s types: %v", nsec.Owner, nsec.TypeBitmap))
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
			proof.Error = fmt.Sprintf("no NSEC at %s proves the DS RRset is absent", child)
			return proof, false
		}
		if _, err := VerifyDenialRRSIGFromResponse(qr.RawResponse, dns.TypeNSEC, parentDNSKEY); err != nil {
			proof.Error = fmt.Sprintf("NSEC RRSIG verification failed: %v", err)
			return proof, false
		}
		proof.Verified = true
		proof.Explanation = fmt.Sprintf("Authenticated NSEC proves no DS at %s (insecure delegation)", child)
		return proof, true
	}

	if len(qr.NSEC3) > 0 {
		proof := &NSECProof{ProofType: "NSEC3", ResponseType: "DS-ABSENCE", Records: make([]string, 0)}
		// RFC 9276: refuse excessive iteration counts before any hashing (R-088).
		// Failing the proof here keeps this fail-closed: an over-cap NSEC3 can
		// never be used to prove an insecure delegation.
		if iters, over := nsec3IterationsOverCap(qr.NSEC3); over {
			proof.Error = fmt.Sprintf("NSEC3 iterations=%d exceeds RFC 9276 cap of %d; refusing (CPU-amplification DoS vector)", iters, NSEC3MaxRecommendedIterations)
			return proof, false
		}
		params := qr.NSEC3[0]
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
		for _, rec := range qr.NSEC3 {
			proof.Records = append(proof.Records, fmt.Sprintf("%s → %s types: %v", rec.HashedOwner, rec.NextHashed, rec.TypeBitmap))
		}
		// 1) Direct match: an NSEC3 whose owner hash equals H(child) with the DS bit clear
		//    and the NS bit set is the delegation-point NSEC3 (non-opt-out zones).
		for _, rec := range qr.NSEC3 {
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
			if _, err := VerifyDenialRRSIGFromResponse(qr.RawResponse, dns.TypeNSEC3, parentDNSKEY); err != nil {
				proof.Error = fmt.Sprintf("NSEC3 RRSIG verification failed: %v", err)
				return proof, false
			}
			proof.Verified = true
			proof.CoveringNSEC = fmt.Sprintf("NSEC3 %s types: %v", rec.HashedOwner, rec.TypeBitmap)
			proof.Explanation = fmt.Sprintf("Authenticated NSEC3 matches %s with the DS bit clear (insecure delegation)", child)
			return proof, true
		}
		// 2) Opt-out cover: an opt-out NSEC3 (Flags bit 0 set) whose hash range covers
		//    H(child) proves an unsigned delegation without its own NSEC3 (RFC 5155 §6).
		for _, rec := range qr.NSEC3 {
			if rec.Flags&0x01 == 0 {
				continue
			}
			if hashBetween(childHash, rec.HashedOwner, rec.NextHashed) {
				if _, err := VerifyDenialRRSIGFromResponse(qr.RawResponse, dns.TypeNSEC3, parentDNSKEY); err != nil {
					proof.Error = fmt.Sprintf("NSEC3 RRSIG verification failed: %v", err)
					return proof, false
				}
				proof.Verified = true
				proof.CoveringNSEC = fmt.Sprintf("NSEC3 %s -> %s [opt-out]", rec.HashedOwner, rec.NextHashed)
				proof.Explanation = fmt.Sprintf("Authenticated opt-out NSEC3 covers %s (insecure delegation)", child)
				return proof, true
			}
		}
		proof.Error = fmt.Sprintf("no NSEC3 proves the DS RRset is absent for %s", child)
		return proof, false
	}

	return &NSECProof{ResponseType: "DS-ABSENCE", Error: "no NSEC/NSEC3 records accompany the DS-absent response"}, false
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
