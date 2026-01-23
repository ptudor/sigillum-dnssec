package validator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
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
	eventCallback EventCallback
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
		v.emitEvent("start", StartEvent{
			Domain:    result.Domain,
			QueryType: result.QueryType,
			Timestamp: start,
			Mode:      "extended",
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
			// Reuse cached result
			v.emitEvent("progress", ProgressEvent{
				Zone:   zone,
				Action: "reusing cached validation",
			})
			result.Chain = append(result.Chain, *cachedResult)

			// Emit zone event for cached result
			v.emitEvent("zone", ZoneEvent{
				Zone:       zone,
				Status:     cachedResult.Status,
				ZoneResult: cachedResult,
			})

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

		// Validate this zone
		zoneResult, err := v.validateZone(ctx, zone, zones)
		if err != nil {
			// Zone validation error
			zoneResult = NewZoneResult(zone)
			zoneResult.Status = StatusIndeterminate
			zoneResult.AddError(err.Error())
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

// validateZone validates a single zone
func (v *Validator) validateZone(ctx context.Context, zone string, hierarchy []string) (*ZoneResult, error) {
	result := NewZoneResult(zone)
	start := time.Now()

	// Get nameservers for this zone
	var nsAddresses []string
	if zone == "." {
		// Use root servers
		nsAddresses = dnspkg.GetRootServers()
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

	// Query DNSKEY from the first responding server
	var dnskeyResult *dnspkg.QueryResult
	for _, addr := range nsAddresses {
		v.emitEvent("progress", ProgressEvent{
			Zone:   zone,
			Server: addr,
			Action: "querying DNSKEY",
		})

		queryResult, err := v.resolver.QueryDNSKEYAuthoritative(ctx, addr, zone)
		if err == nil && queryResult.Error == "" && queryResult.RCode == 0 {
			dnskeyResult = queryResult
			break
		}
	}

	if dnskeyResult == nil {
		result.Status = StatusIndeterminate
		result.AddError("failed to query DNSKEY from any nameserver")
		return result, nil
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
		dsRecords, err := v.queryDSFromParent(ctx, zone, parentZone, nsAddresses)
		if err != nil {
			result.Status = StatusIndeterminate
			result.AddError(fmt.Sprintf("failed to query DS from parent: %v", err))
			return result, nil
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

// queryDSFromParent queries DS records for a zone from its parent
func (v *Validator) queryDSFromParent(ctx context.Context, zone, parentZone string, fallbackServers []string) ([]dnspkg.DSRecord, error) {
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
			return result.DS, nil
		}
		// NXDOMAIN or no DS records
		if result != nil && result.RCode == dns.RcodeNameError {
			return nil, nil // Zone doesn't exist in parent
		}
	}

	return nil, fmt.Errorf("failed to query DS from parent zone")
}

// ValidateMultipleServers queries all servers in parallel and checks for consensus
func (v *Validator) ValidateMultipleServers(ctx context.Context, zone string, servers []string) ([]AddressResult, []Disagreement) {
	results := make([]AddressResult, len(servers))
	var wg sync.WaitGroup
	var mu sync.Mutex
	disagreements := make([]Disagreement, 0)

	// Limit concurrency
	semaphore := make(chan struct{}, v.maxConcurrent)

	for i, server := range servers {
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
