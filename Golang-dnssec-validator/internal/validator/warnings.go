package validator

import (
	"fmt"

	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// RFC 8624 algorithm deprecation status
var deprecatedAlgorithms = map[uint8]string{
	5: "RSASHA1 (RFC 8624: MUST NOT use for signing, considered weak)",
	7: "RSASHA1-NSEC3-SHA1 (RFC 8624: MUST NOT use for signing, considered weak)",
}

// RFC 8624 digest type deprecation status
var deprecatedDigestTypes = map[uint8]string{
	1: "SHA-1 (RFC 8624: MUST NOT use, cryptographically weak)",
}

// NSEC3 iteration limits per RFC 9276
const (
	// RFC 9276 Section 3.1: iterations SHOULD be 0, MUST NOT exceed 100
	NSEC3MaxRecommendedIterations = 100
	NSEC3IdealIterations          = 10
)

// NSEC3 Flags per RFC 5155
const (
	// Bit 0: Opt-Out flag
	NSEC3FlagOptOut = 0x01
)

// CheckAlgorithmDeprecation returns warnings for deprecated DNSKEY algorithms
func CheckAlgorithmDeprecation(dnskeys []dnspkg.DNSKEYRecord) []string {
	var warnings []string
	seen := make(map[uint8]bool)

	for _, key := range dnskeys {
		if msg, deprecated := deprecatedAlgorithms[key.Algorithm]; deprecated && !seen[key.Algorithm] {
			warnings = append(warnings, fmt.Sprintf("Zone uses deprecated algorithm %d: %s",
				key.Algorithm, msg))
			seen[key.Algorithm] = true
		}
	}

	return warnings
}

// CheckDigestTypeDeprecation returns warnings for deprecated DS digest types
func CheckDigestTypeDeprecation(dsRecords []dnspkg.DSRecord) []string {
	var warnings []string
	seen := make(map[uint8]bool)

	for _, ds := range dsRecords {
		if msg, deprecated := deprecatedDigestTypes[ds.DigestType]; deprecated && !seen[ds.DigestType] {
			warnings = append(warnings, fmt.Sprintf("DS uses deprecated digest type %d: %s",
				ds.DigestType, msg))
			seen[ds.DigestType] = true
		}
	}

	return warnings
}

// CheckNSEC3Iterations returns warnings for excessive NSEC3 iterations per RFC 9276
func CheckNSEC3Iterations(nsec3Records []dnspkg.NSEC3Record) []string {
	var warnings []string

	for _, nsec3 := range nsec3Records {
		if nsec3.Iterations > NSEC3MaxRecommendedIterations {
			warnings = append(warnings, fmt.Sprintf(
				"NSEC3 iterations=%d exceeds RFC 9276 maximum (%d); "+
					"high iterations provide no security benefit and are a DoS vector",
				nsec3.Iterations, NSEC3MaxRecommendedIterations))
			break // One warning is enough
		} else if nsec3.Iterations > NSEC3IdealIterations {
			warnings = append(warnings, fmt.Sprintf(
				"NSEC3 iterations=%d above RFC 9276 recommendation (%d); consider reducing",
				nsec3.Iterations, NSEC3IdealIterations))
			break
		}
	}

	return warnings
}

// CheckNSEC3OptOut checks if NSEC3 opt-out is enabled and returns explanatory info
// Returns (isOptOut, explanation)
func CheckNSEC3OptOut(nsec3Records []dnspkg.NSEC3Record) (bool, string) {
	for _, nsec3 := range nsec3Records {
		if nsec3.Flags&NSEC3FlagOptOut != 0 {
			return true, "NSEC3 opt-out enabled (RFC 5155): insecure delegations " +
				"may not be cryptographically proven. Common for large TLDs."
		}
	}
	return false, ""
}

// CheckRRSIGAlgorithmDeprecation checks RRSIG records for deprecated algorithms
func CheckRRSIGAlgorithmDeprecation(rrsigs []dnspkg.RRSIGRecord) []string {
	var warnings []string
	seen := make(map[uint8]bool)

	for _, rrsig := range rrsigs {
		if msg, deprecated := deprecatedAlgorithms[rrsig.Algorithm]; deprecated && !seen[rrsig.Algorithm] {
			warnings = append(warnings, fmt.Sprintf("RRSIG uses deprecated algorithm %d: %s",
				rrsig.Algorithm, msg))
			seen[rrsig.Algorithm] = true
		}
	}

	return warnings
}
