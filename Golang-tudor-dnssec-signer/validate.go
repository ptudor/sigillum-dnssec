package main

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ValidationResult holds the results of all DNSSEC validation checks for a zone.
type ValidationResult struct {
	Domain      string            `json:"domain"`
	Timestamp   time.Time         `json:"timestamp"`
	DSCheck     DSCheckResult     `json:"ds_check"`
	DNSKEYCheck DNSKEYCheckResult `json:"dnskey_check"`
	RRSIGCheck  RRSIGCheckResult  `json:"rrsig_check"`
	SOACheck    SOACheckResult    `json:"soa_check"`
	Overall     string            `json:"overall"` // "pass", "fail", "partial", "error"
	Errors      []string          `json:"errors,omitempty"`
}

// DSCheckResult holds the result of querying the parent zone for DS records.
type DSCheckResult struct {
	Status     string   `json:"status"` // "pass", "fail", "error"
	Found      bool     `json:"found"`
	MatchesKSK bool     `json:"matches_ksk"`
	ParentNS   string   `json:"parent_ns"`
	DSRecords  []string `json:"ds_records,omitempty"`
	ExpectedDS []string `json:"expected_ds,omitempty"` // DS computed from local KSK (publish at registrar)
	Details    string   `json:"details"`
}

// DNSKEYCheckResult holds the result of querying authoritative NS for DNSKEY records.
type DNSKEYCheckResult struct {
	Status   string   `json:"status"`
	KSKFound bool     `json:"ksk_found"`
	ZSKFound bool     `json:"zsk_found"`
	AuthNS   string   `json:"auth_ns"`
	KeyTags  []uint16 `json:"key_tags,omitempty"`
	Details  string   `json:"details"`
}

// RRSIGCheckResult holds the result of checking RRSIG presence on key RR types.
type RRSIGCheckResult struct {
	Status       string `json:"status"`
	SOASigned    bool   `json:"soa_signed"`
	DNSKEYSigned bool   `json:"dnskey_signed"`
	Details      string `json:"details"`
}

// SOACheckResult holds the result of comparing local and remote SOA serials.
type SOACheckResult struct {
	Status       string `json:"status"`
	LocalSerial  uint32 `json:"local_serial"`
	RemoteSerial uint32 `json:"remote_serial"`
	AuthNS       string `json:"auth_ns"`
	Details      string `json:"details"`
}

// ValidateOutput is the top-level output for the validate command.
type ValidateOutput struct {
	Timestamp time.Time                    `json:"timestamp"`
	Zones     map[string]*ValidationResult `json:"zones"`
	Summary   ValidateSummary              `json:"summary"`
}

// ValidateSummary counts validation outcomes across all zones.
type ValidateSummary struct {
	Total   int `json:"total"`
	Pass    int `json:"pass"`
	Fail    int `json:"fail"`
	Partial int `json:"partial"`
	Error   int `json:"error"`
}

// Validator performs internet DNSSEC validation checks against live DNS.
type Validator struct {
	cfg      *Config
	state    *State
	resolver string
	timeout  time.Duration
}

// NewValidator creates a Validator with the given configuration.
func NewValidator(cfg *Config, state *State, resolver string, timeout time.Duration) *Validator {
	return &Validator{
		cfg:      cfg,
		state:    state,
		resolver: resolver,
		timeout:  timeout,
	}
}

// ValidateAll runs validation for every zone in state.
func (v *Validator) ValidateAll() *ValidateOutput {
	output := &ValidateOutput{
		Timestamp: time.Now().UTC(),
		Zones:     make(map[string]*ValidationResult),
	}

	v.state.mu.RLock()
	domains := make([]string, 0, len(v.state.Zones))
	for d := range v.state.Zones {
		domains = append(domains, d)
	}
	v.state.mu.RUnlock()

	for _, domain := range domains {
		result := v.ValidateZone(domain)
		output.Zones[domain] = result
		output.Summary.Total++
		switch result.Overall {
		case "pass":
			output.Summary.Pass++
		case "fail":
			output.Summary.Fail++
		case "partial":
			output.Summary.Partial++
		case "error":
			output.Summary.Error++
		}
	}

	return output
}

// ValidateZone runs all validation checks for a single domain.
func (v *Validator) ValidateZone(domain string) *ValidationResult {
	result := &ValidationResult{
		Domain:    domain,
		Timestamp: time.Now().UTC(),
	}

	zoneState := v.state.GetZone(domain)
	if zoneState == nil {
		result.Overall = "error"
		result.Errors = append(result.Errors, "zone not found in state")
		result.DSCheck.Status = "error"
		result.DSCheck.Details = "zone not in state"
		result.DNSKEYCheck.Status = "error"
		result.DNSKEYCheck.Details = "zone not in state"
		result.RRSIGCheck.Status = "error"
		result.RRSIGCheck.Details = "zone not in state"
		result.SOACheck.Status = "error"
		result.SOACheck.Details = "zone not in state"
		return result
	}

	// Load actual KSK for DS comparison
	var localKSK *dns.DNSKEY
	var localKSKTag uint16
	var localZSKTag uint16

	if zoneState.KSK != nil {
		localKSKTag = zoneState.KSK.ID
		keyGen := NewKeyGenerator(v.cfg)
		ksk, _, err := keyGen.LoadKeyPair(domain, "ksk")
		if err != nil {
			slog.Debug("[VALIDATE] Failed to load KSK", "domain", domain, "error", err)
		} else {
			localKSK = ksk
		}
	}
	if zoneState.ZSK != nil {
		localZSKTag = zoneState.ZSK.ID
	}

	// Run checks
	result.DSCheck = v.checkDSAtParent(domain, localKSK)
	result.DNSKEYCheck = v.checkDNSKEYVisible(domain, localKSKTag, localZSKTag)
	result.RRSIGCheck = v.checkRRSIGPresent(domain)
	result.SOACheck = v.checkSOASerial(domain, zoneState.Serial)

	// Compute overall status
	result.Overall = computeOverall(
		result.DSCheck.Status,
		result.DNSKEYCheck.Status,
		result.RRSIGCheck.Status,
		result.SOACheck.Status,
	)

	// Override: if the authoritative NS is unreachable, the zone is broken
	// regardless of whether DS exists at the parent. Validating resolvers
	// will return SERVFAIL for every query to this zone.
	if result.DNSKEYCheck.Status == "error" &&
		result.RRSIGCheck.Status == "error" &&
		result.SOACheck.Status == "error" {
		result.Overall = "fail"
	}

	return result
}

// checkDSAtParent queries the parent zone for DS records and compares them to the local KSK.
func (v *Validator) checkDSAtParent(domain string, localKSK *dns.DNSKEY) DSCheckResult {
	result := DSCheckResult{Status: "error"}

	parentZone := findParentZone(domain)

	// Find parent NS
	parentNS, err := v.resolveNS(parentZone)
	if err != nil {
		result.Details = fmt.Sprintf("failed to resolve parent NS for %s: %v", parentZone, err)
		return result
	}
	result.ParentNS = parentNS

	// Query DS records at parent
	msg, err := queryDirect(parentNS, dns.Fqdn(domain), dns.TypeDS, v.timeout)
	if err != nil {
		result.Details = fmt.Sprintf("DS query to %s failed: %v", parentNS, err)
		return result
	}

	// Collect DS records from answer
	var dsRecords []*dns.DS
	for _, rr := range msg.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			dsRecords = append(dsRecords, ds)
			result.DSRecords = append(result.DSRecords, ds.String())
		}
	}

	// Compute expected DS from local KSK (useful whether or not parent has DS)
	var expectedDS *dns.DS
	if localKSK != nil {
		expectedDS = localKSK.ToDS(dns.SHA256)
		if expectedDS != nil {
			result.ExpectedDS = append(result.ExpectedDS, expectedDS.String())
			// Also include SHA-384 for registrars that want digest type 4
			if ds4 := localKSK.ToDS(dns.SHA384); ds4 != nil {
				result.ExpectedDS = append(result.ExpectedDS, ds4.String())
			}
		}
	}

	if len(dsRecords) == 0 {
		result.Status = "fail"
		result.Found = false
		result.Details = "no DS records found at parent"
		return result
	}

	result.Found = true

	// Compare with local KSK if available
	if expectedDS != nil {
		for _, ds := range dsRecords {
			if ds.KeyTag == expectedDS.KeyTag &&
				ds.Algorithm == expectedDS.Algorithm &&
				ds.DigestType == expectedDS.DigestType &&
				strings.EqualFold(ds.Digest, expectedDS.Digest) {
				result.MatchesKSK = true
				break
			}
		}
		if result.MatchesKSK {
			result.Status = "pass"
			result.Details = fmt.Sprintf("DS at parent matches local KSK (tag %d)", expectedDS.KeyTag)
		} else {
			result.Status = "fail"
			result.Details = fmt.Sprintf("DS records found but none match local KSK (tag %d)", expectedDS.KeyTag)
		}
	} else if localKSK != nil {
		// Had a KSK but couldn't compute DS
		result.Status = "pass"
		result.Details = fmt.Sprintf("%d DS record(s) found (could not compute local DS for comparison)", len(dsRecords))
	} else {
		// Can't compare without local KSK, but DS exists
		result.Status = "pass"
		result.Details = fmt.Sprintf("%d DS record(s) found (no local KSK to compare)", len(dsRecords))
	}

	return result
}

// checkDNSKEYVisible queries the zone's authoritative NS for DNSKEY records.
func (v *Validator) checkDNSKEYVisible(domain string, kskTag, zskTag uint16) DNSKEYCheckResult {
	result := DNSKEYCheckResult{Status: "error"}

	authNS, err := v.resolveNS(dns.Fqdn(domain))
	if err != nil {
		result.Details = fmt.Sprintf("failed to resolve NS for %s: %v", domain, err)
		return result
	}
	result.AuthNS = authNS

	msg, err := queryDirect(authNS, dns.Fqdn(domain), dns.TypeDNSKEY, v.timeout)
	if err != nil {
		result.Details = fmt.Sprintf("DNSKEY query to %s failed: %v", authNS, err)
		return result
	}

	for _, rr := range msg.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			tag := dnskey.KeyTag()
			result.KeyTags = append(result.KeyTags, tag)
			if tag == kskTag {
				result.KSKFound = true
			}
			if tag == zskTag {
				result.ZSKFound = true
			}
		}
	}

	if len(result.KeyTags) == 0 {
		result.Status = "fail"
		result.Details = "no DNSKEY records found at authoritative NS"
		return result
	}

	if result.KSKFound && result.ZSKFound {
		result.Status = "pass"
		result.Details = fmt.Sprintf("KSK (tag %d) and ZSK (tag %d) visible", kskTag, zskTag)
	} else if result.KSKFound || result.ZSKFound {
		result.Status = "partial"
		missing := "ZSK"
		if !result.KSKFound {
			missing = "KSK"
		}
		result.Details = fmt.Sprintf("%s (expected tag) not found in DNSKEY set", missing)
	} else {
		result.Status = "fail"
		result.Details = fmt.Sprintf("DNSKEY records found but neither KSK (tag %d) nor ZSK (tag %d) match", kskTag, zskTag)
	}

	return result
}

// checkRRSIGPresent checks that SOA and DNSKEY have RRSIG records at the authoritative NS.
func (v *Validator) checkRRSIGPresent(domain string) RRSIGCheckResult {
	result := RRSIGCheckResult{Status: "error"}

	authNS, err := v.resolveNS(dns.Fqdn(domain))
	if err != nil {
		result.Details = fmt.Sprintf("failed to resolve NS for %s: %v", domain, err)
		return result
	}

	// Check SOA RRSIG
	soaMsg, err := queryDirect(authNS, dns.Fqdn(domain), dns.TypeSOA, v.timeout)
	if err != nil {
		result.Details = fmt.Sprintf("SOA query to %s failed: %v", authNS, err)
		return result
	}
	for _, rr := range soaMsg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == dns.TypeSOA {
			result.SOASigned = true
			break
		}
	}

	// Check DNSKEY RRSIG
	dnskeyMsg, err := queryDirect(authNS, dns.Fqdn(domain), dns.TypeDNSKEY, v.timeout)
	if err != nil {
		result.Details = fmt.Sprintf("DNSKEY query to %s failed: %v", authNS, err)
		return result
	}
	for _, rr := range dnskeyMsg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == dns.TypeDNSKEY {
			result.DNSKEYSigned = true
			break
		}
	}

	if result.SOASigned && result.DNSKEYSigned {
		result.Status = "pass"
		result.Details = "RRSIG found for both SOA and DNSKEY"
	} else if result.SOASigned || result.DNSKEYSigned {
		result.Status = "partial"
		missing := "DNSKEY"
		if !result.SOASigned {
			missing = "SOA"
		}
		result.Details = fmt.Sprintf("RRSIG missing for %s", missing)
	} else {
		result.Status = "fail"
		result.Details = "no RRSIG records found for SOA or DNSKEY"
	}

	return result
}

// checkSOASerial compares the remote SOA serial with the locally signed serial.
func (v *Validator) checkSOASerial(domain string, localSerial uint32) SOACheckResult {
	result := SOACheckResult{
		Status:      "error",
		LocalSerial: localSerial,
	}

	authNS, err := v.resolveNS(dns.Fqdn(domain))
	if err != nil {
		result.Details = fmt.Sprintf("failed to resolve NS for %s: %v", domain, err)
		return result
	}
	result.AuthNS = authNS

	msg, err := queryDirect(authNS, dns.Fqdn(domain), dns.TypeSOA, v.timeout)
	if err != nil {
		result.Details = fmt.Sprintf("SOA query to %s failed: %v", authNS, err)
		return result
	}

	for _, rr := range msg.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			result.RemoteSerial = soa.Serial
			if soa.Serial == localSerial {
				result.Status = "pass"
				result.Details = fmt.Sprintf("serial %d matches", localSerial)
			} else {
				result.Status = "fail"
				result.Details = fmt.Sprintf("serial mismatch: local=%d remote=%d", localSerial, soa.Serial)
			}
			return result
		}
	}

	result.Details = "no SOA record in response"
	return result
}

// findParentZone returns the parent zone for a domain.
// "example.com" -> "com.", "sub.example.com" -> "example.com.", "com" -> "."
func findParentZone(domain string) string {
	fqdn := dns.Fqdn(domain)
	labels := dns.SplitDomainName(fqdn)
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// resolveNS returns the IP:53 address of one nameserver for the given zone.
// Uses the configured recursive resolver to find NS records and resolve one to an A record.
func (v *Validator) resolveNS(zone string) (string, error) {
	resolver := v.resolverAddr()

	// Query NS records
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeNS)
	m.RecursionDesired = true

	c := new(dns.Client)
	c.Timeout = v.timeout

	r, _, err := c.Exchange(m, resolver)
	if err != nil {
		return "", fmt.Errorf("NS lookup for %s: %w", zone, err)
	}

	// Collect NS hostnames from answer and authority sections
	var nsNames []string
	for _, rr := range r.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames = append(nsNames, ns.Ns)
		}
	}
	if len(nsNames) == 0 {
		for _, rr := range r.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsNames = append(nsNames, ns.Ns)
			}
		}
	}

	if len(nsNames) == 0 {
		return "", fmt.Errorf("no NS records found for %s", zone)
	}

	// Try to resolve first NS to an A record
	for _, nsName := range nsNames {
		// Check additional section first
		for _, rr := range r.Extra {
			if a, ok := rr.(*dns.A); ok && dns.Fqdn(a.Hdr.Name) == dns.Fqdn(nsName) {
				return net.JoinHostPort(a.A.String(), "53"), nil
			}
		}

		// Fall back to resolving the NS hostname
		am := new(dns.Msg)
		am.SetQuestion(dns.Fqdn(nsName), dns.TypeA)
		am.RecursionDesired = true

		ar, _, err := c.Exchange(am, resolver)
		if err != nil {
			continue
		}
		for _, rr := range ar.Answer {
			if a, ok := rr.(*dns.A); ok {
				return net.JoinHostPort(a.A.String(), "53"), nil
			}
		}
	}

	return "", fmt.Errorf("could not resolve any NS for %s to an IP address", zone)
}

// resolverAddr returns the recursive resolver address to use.
// Priority: explicit config > system default > 1.1.1.1:53
func (v *Validator) resolverAddr() string {
	if v.resolver != "" {
		// Ensure it has a port
		if _, _, err := net.SplitHostPort(v.resolver); err != nil {
			return net.JoinHostPort(v.resolver, "53")
		}
		return v.resolver
	}

	// Try system resolver from /etc/resolv.conf
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(conf.Servers) > 0 {
		return net.JoinHostPort(conf.Servers[0], conf.Port)
	}

	return "1.1.1.1:53"
}

// queryDirect sends a DNS query directly to a specific server with the DO (DNSSEC OK) bit set.
func queryDirect(server, qname string, qtype uint16, timeout time.Duration) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.SetEdns0(4096, true) // DO bit for DNSSEC records
	m.RecursionDesired = false

	c := new(dns.Client)
	c.Timeout = timeout

	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	if r.Rcode != dns.RcodeSuccess {
		return r, fmt.Errorf("DNS response code: %s", dns.RcodeToString[r.Rcode])
	}

	return r, nil
}

// computeOverall determines the overall validation status from individual check statuses.
func computeOverall(statuses ...string) string {
	passes := 0
	fails := 0
	errors := 0

	for _, s := range statuses {
		switch s {
		case "pass":
			passes++
		case "fail":
			fails++
		case "partial":
			// partial counts as neither full pass nor full fail
		case "error":
			errors++
		}
	}

	total := len(statuses)

	if passes == total {
		return "pass"
	}
	if errors == total {
		return "error"
	}
	if fails == total {
		return "fail"
	}
	if passes == 0 && errors > 0 && fails == 0 {
		return "error"
	}
	return "partial"
}
