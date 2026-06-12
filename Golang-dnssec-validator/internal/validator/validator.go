package validator

import (
	"context"
	"fmt"
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
	quickMode     bool // true = query first responding NS only; false = query all
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
	}
}

// SetQuickMode enables quick mode (query first responding NS only)
func (v *Validator) SetQuickMode(quick bool) {
	v.quickMode = quick
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
		QueryType:   "A",
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
			if len(cachedResult.DNSKEY) > 0 {
				parentDNSKEY = cachedResult.DNSKEY
			}

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
		if len(zoneResult.DNSKEY) > 0 {
			parentDNSKEY = zoneResult.DNSKEY
		}

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

	// Query A record from authoritative servers to check for CNAME
	var queryResult *dnspkg.QueryResult
	for _, addr := range nsAddresses {
		result, err := v.resolver.QueryRecordAuthoritative(ctx, addr, domain, dns.TypeA)
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

// verifyActualRecord queries and verifies the actual record (A, AAAA, etc.) RRSIG
func (v *Validator) verifyActualRecord(ctx context.Context, domain, zone string, dnskeys []dnspkg.DNSKEYRecord) *RecordValidation {
	if len(dnskeys) == 0 {
		return nil // Can't verify without zone DNSKEY
	}

	// Get nameservers for the zone
	nsRecords, err := v.resolver.ResolveNSWithAddresses(ctx, zone)
	if err != nil || len(nsRecords) == 0 {
		return &RecordValidation{
			RecordType: "A",
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

	// Query A record from authoritative servers
	var queryResult *dnspkg.QueryResult
	for _, addr := range nsAddresses {
		result, err := v.resolver.QueryRecordAuthoritative(ctx, addr, domain, dns.TypeA)
		if err == nil && result.Error == "" {
			queryResult = result
			break
		}
	}

	if queryResult == nil {
		return &RecordValidation{
			RecordType: "A",
			Error:      "failed to query A record from authoritative servers",
		}
	}

	validation := &RecordValidation{
		RecordType: "A",
	}

	// Check for NXDOMAIN/NODATA with NSEC/NSEC3 proofs
	if queryResult.RCode == dns.RcodeNameError || (queryResult.RCode == dns.RcodeSuccess && len(queryResult.CNAME) == 0) {
		// Check for denial proofs if this is NXDOMAIN or NODATA
		if len(queryResult.NSEC) > 0 {
			// Verify NSEC denial proof with full RRSIG verification
			proof := VerifyNSECDenialWithRRSIG(domain, dns.TypeA, queryResult.NSEC, queryResult.RRSIG, dnskeys, queryResult.RawResponse, queryResult.RCode)
			validation.DenialProof = proof
			if proof.Verified {
				validation.RRSIGVerified = true
			} else if proof.Error != "" {
				validation.Error = proof.Error
			}
			return validation
		} else if len(queryResult.NSEC3) > 0 {
			// Verify NSEC3 denial proof with full RRSIG verification
			proof := VerifyNSEC3DenialWithRRSIG(domain, dns.TypeA, queryResult.NSEC3, queryResult.RRSIG, dnskeys, zone, queryResult.RawResponse, queryResult.RCode)
			validation.DenialProof = proof
			if proof.Verified {
				validation.RRSIGVerified = true
			} else if proof.Error != "" {
				validation.Error = proof.Error
			}
			return validation
		}
	}

	// Find RRSIG for A record (type 1)
	rrsigA := FindRRSIGForType(dns.TypeA, queryResult.RRSIG)
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
				// Find signing key
				signingKey := FindZSKByKeyTag(rrsigCNAME.KeyTag, dnskeys)
				if signingKey == nil {
					signingKey = FindDNSKEYByKeyTag(rrsigCNAME.KeyTag, dnskeys)
				}
				if signingKey != nil {
					count, err := VerifyRRsetRRSIGFromResponse(queryResult.RawResponse, dns.TypeCNAME, *signingKey, rrsigCNAME.KeyTag)
					if err == nil {
						validation.RRSIGVerified = true
						validation.SigningKeyTag = signingKey.KeyTag
						validation.RecordCount = count
						v.verifyWildcard(validation, domain, *rrsigCNAME, queryResult, dnskeys)
					} else {
						validation.Error = fmt.Sprintf("CNAME RRSIG cryptographic verification failed: %v", err)
					}
				} else {
					validation.Error = fmt.Sprintf("CNAME signing key (tag %d) not found", rrsigCNAME.KeyTag)
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

	// Find signing key (should be a ZSK)
	signingKey := FindZSKByKeyTag(rrsigA.KeyTag, dnskeys)
	if signingKey == nil {
		signingKey = FindDNSKEYByKeyTag(rrsigA.KeyTag, dnskeys)
	}
	if signingKey == nil {
		validation.Error = fmt.Sprintf("A record signing key (tag %d) not found in zone DNSKEY", rrsigA.KeyTag)
		return validation
	}

	if rrsigA.SignerName == zone || rrsigA.SignerName == dns.Fqdn(zone) {
		count, err := VerifyRRsetRRSIGFromResponse(queryResult.RawResponse, dns.TypeA, *signingKey, rrsigA.KeyTag)
		if err == nil {
			validation.RRSIGVerified = true
			validation.SigningKeyTag = signingKey.KeyTag
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
			dsResult, err := v.queryDSFromParent(ctx, zone, parentZone, nsAddresses)
			if err != nil || len(dsResult) == 0 {
				// No DS in parent = insecure delegation
				result.Status = StatusInsecure
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

	// Verify DNSKEY RRSIG
	if err := VerifyDNSKEYRRSIG(result.DNSKEY, result.RRSIG); err != nil {
		result.Status = StatusBogus
		result.AddError(fmt.Sprintf("DNSKEY RRSIG verification failed: %v", err))
		return result, nil
	}

	// RFC 4034 §3.1.3: Detect wildcard synthesis
	if rrsig := FindRRSIGForType(dns.TypeDNSKEY, result.RRSIG); rrsig != nil {
		if wildcard := DetectWildcardSynthesis(zone, *rrsig); wildcard != "" {
			result.WildcardSource = wildcard
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("Response synthesized from wildcard %s", wildcard))
		}
	}

	// Validate chain of trust
	if zone == "." {
		// Root zone - verify against trust anchors
		activeAnchors := dnspkg.GetActiveAnchors(v.anchors)
		link, err := VerifyRootTrustAnchor(result.DNSKEY, activeAnchors)
		if err != nil {
			result.Status = StatusBogus
			result.AddError(fmt.Sprintf("root trust anchor verification failed: %v", err))
			return result, nil
		}
		result.ChainLink = link
	} else {
		// Non-root zone - verify DS from parent
		parentZone := GetParentZone(zone)
		dsRecords, dsValidation, err := v.queryDSFromParentWithValidation(ctx, zone, parentZone, nsAddresses, parentDNSKEY)
		if err != nil {
			result.Status = StatusIndeterminate
			result.AddError(fmt.Sprintf("failed to query DS from parent: %v", err))
			return result, nil
		}

		// Store DS validation result
		if dsValidation != nil {
			result.DSValidation = dsValidation
			if dsValidation.Error != "" {
				result.Warnings = append(result.Warnings, fmt.Sprintf("DS RRSIG: %s", dsValidation.Error))
			}
		}

		if len(dsRecords) == 0 {
			// No DS = insecure delegation
			result.Status = StatusInsecure
			return result, nil
		}

		result.DS = dsRecords

		// Validate DS matches DNSKEY
		link, err := ValidateChainLink(dsRecords, result.DNSKEY, zone)
		if err != nil {
			result.Status = StatusBogus
			result.AddError(fmt.Sprintf("chain of trust validation failed: %v", err))
			return result, nil
		}
		result.ChainLink = link

		// Query RDAP for out-of-band DS verification (only for registrable domains)
		if v.rdapClient != nil && IsRegistrableDomain(zone) {
			rdapResult := v.queryRDAPSecureDNS(ctx, zone, dsRecords)
			result.RDAPSecureDNS = rdapResult
			if rdapResult != nil && rdapResult.DSMatch == DSMatchNone {
				result.Warnings = append(result.Warnings, "RDAP DS records do not match DNS DS records")
			}
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

// queryDSFromParentWithValidation queries DS records and verifies the DS RRSIG
func (v *Validator) queryDSFromParentWithValidation(ctx context.Context, zone, parentZone string, fallbackServers []string, parentDNSKEY []dnspkg.DNSKEYRecord) ([]dnspkg.DSRecord, *DSValidation, error) {
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
				// Find the RRSIG for DS
				dsRRSIG := FindRRSIGForType(dns.TypeDS, result.RRSIG)
				if dsRRSIG != nil {
					// Find signing key
					signingKey := FindZSKByKeyTag(dsRRSIG.KeyTag, parentDNSKEY)
					if signingKey == nil {
						signingKey = FindDNSKEYByKeyTag(dsRRSIG.KeyTag, parentDNSKEY)
					}
					if signingKey != nil {
						// Verify RRSIG time validity
						if VerifyRRSIGValid(*dsRRSIG) {
							if _, err := VerifyRRsetRRSIGFromResponse(result.RawResponse, dns.TypeDS, *signingKey, dsRRSIG.KeyTag); err == nil {
								validation.RRSIGVerified = true
								validation.ParentSigningKey = signingKey.KeyTag
							} else {
								validation.Error = fmt.Sprintf("DS RRSIG cryptographic verification failed: %v", err)
							}
						} else {
							if dsRRSIG.IsExpired {
								validation.Error = fmt.Sprintf("DS RRSIG expired at %s", dsRRSIG.Expiration.Format("2006-01-02T15:04:05Z"))
							} else {
								validation.Error = fmt.Sprintf("DS RRSIG not yet valid (inception: %s)", dsRRSIG.Inception.Format("2006-01-02T15:04:05Z"))
							}
						}
					} else {
						validation.Error = fmt.Sprintf("DS signing key (tag %d) not found in parent DNSKEY", dsRRSIG.KeyTag)
					}
				} else {
					validation.Error = "no RRSIG for DS record"
				}
			}

			return result.DS, validation, nil
		}
		// NXDOMAIN or no DS records
		if result != nil && result.RCode == dns.RcodeNameError {
			return nil, validation, nil // Zone doesn't exist in parent
		}
	}

	return nil, validation, fmt.Errorf("failed to query DS from parent zone")
}

// queryDSFromParent queries DS records for a zone from its parent (compatibility wrapper)
func (v *Validator) queryDSFromParent(ctx context.Context, zone, parentZone string, fallbackServers []string) ([]dnspkg.DSRecord, error) {
	ds, _, err := v.queryDSFromParentWithValidation(ctx, zone, parentZone, fallbackServers, nil)
	return ds, err
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
