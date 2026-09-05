package validate

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
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
	// Servfail is the structured verdict "validating resolvers fail this
	// zone": a proven broken trust chain or unreachable authoritative servers
	// while the local resolver works (RA6X-032). ResolverOutage marks the
	// uncertain case where the validator's own resolver did not respond.
	Servfail       bool     `json:"servfail"`
	ResolverOutage bool     `json:"resolver_outage"`
	Errors         []string `json:"errors,omitempty"`
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
	// MaterialMatched is true when the served keys were compared by complete
	// owner-bound key material (flags, algorithm, public key), not by key
	// tag alone (RA6X-032); false only when no local key could be loaded.
	MaterialMatched bool   `json:"material_matched"`
	Details         string `json:"details"`
}

// RRSIGCheckResult holds the result of verifying the SOA and DNSKEY
// signatures served by the authoritative nameserver. SOASigned and
// DNSKEYSigned are true only for a signature that cryptographically verifies
// over the served RRset under an expected key and is inside its validity
// window (RA6X-032).
type RRSIGCheckResult struct {
	Status       string `json:"status"`
	SOASigned    bool   `json:"soa_signed"`
	DNSKEYSigned bool   `json:"dnskey_signed"`
	// Verified reports that cryptographic verification was performed.
	Verified bool `json:"verified"`
	// Broken marks a proven defect — a required signature is missing,
	// expired or does not verify — as opposed to the refresh-window notice.
	Broken  bool   `json:"broken"`
	Details string `json:"details"`
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
	cfg      *config.Config
	state    *statepkg.State
	resolver string
	timeout  time.Duration
	// authPort is the port authoritative servers are queried on ("53");
	// tests point it at hermetic servers.
	authPort string
}

// portOr returns the configured authoritative port.
func (v *Validator) portOr() string {
	if v.authPort == "" {
		return "53"
	}
	return v.authPort
}

// NewValidator creates a Validator with the given configuration.
func NewValidator(cfg *config.Config, state *statepkg.State, resolver string, timeout time.Duration) *Validator {
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

	domains := v.state.ZoneNames()

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

	// Deep copy — validation runs from web handlers concurrently with the
	// signing loop mutating the live state.
	zoneState := v.state.GetZoneCopy(domain)
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

	// Load the actual local key material: DS comparison and served-key
	// checks bind to complete keys, never to 16-bit tags alone (RA6X-032).
	var localKSK, localZSK *dns.DNSKEY
	var localKSKTag uint16
	var localZSKTag uint16

	keyGen := signerpkg.NewKeyGenerator(v.cfg)
	if zoneState.KSK != nil {
		localKSKTag = zoneState.KSK.ID
		ksk, err := keyGen.LoadPublicKey(domain, "ksk")
		if err != nil {
			slog.Debug("[VALIDATE] Failed to load KSK", "domain", domain, "error", err)
		} else {
			localKSK = ksk
		}
	}
	if zoneState.ZSK != nil {
		localZSKTag = zoneState.ZSK.ID
		zsk, err := keyGen.LoadPublicKey(domain, "zsk")
		if err != nil {
			slog.Debug("[VALIDATE] Failed to load ZSK", "domain", domain, "error", err)
		} else {
			localZSK = zsk
		}
	}

	// Build the set of KSKs whose DS we accept at the parent: the current KSK
	// plus, during a KSK/algorithm rollover, the old KSK — the parent legitimately
	// holds old+new during ds_add_wait, so matching only the current one reports a
	// false "fail" (R-046). Mirrors BuildDSSet.
	var acceptableKSKs []*dns.DNSKEY
	if localKSK != nil {
		acceptableKSKs = append(acceptableKSKs, localKSK)
	}
	if r := zoneState.Rollover; r != nil && (r.Type == "ksk" || r.Type == "algorithm") && r.OldKeyID != 0 {
		if oldKSK, err := keyGen.LoadPublicKeyByID(domain, "ksk", r.OldKeyID); err == nil && oldKSK != nil {
			acceptableKSKs = append(acceptableKSKs, oldKSK)
		} else if err != nil {
			slog.Debug("[VALIDATE] Failed to load old KSK during rollover", "domain", domain, "old_key_id", r.OldKeyID, "error", err)
		}
	}
	// R-047: the zone has a KSK in state but no usable public key could be loaded
	// — we must NOT fail open to "pass" just because some DS exists at the parent.
	kskUnloadable := zoneState.KSK != nil && len(acceptableKSKs) == 0

	// The keys whose signatures we accept for each role: the current keys plus
	// the rollover alternatives that legitimately sign during a phase (the old
	// KSK during a KSK/algorithm rollover; the old ZSK while it still signs or
	// is still published).
	signingKSKs := acceptableKSKs
	var signingZSKs []*dns.DNSKEY
	if localZSK != nil {
		signingZSKs = append(signingZSKs, localZSK)
	}
	if r := zoneState.Rollover; r != nil {
		var oldZSKID uint16
		switch r.Type {
		case "zsk":
			oldZSKID = r.OldKeyID
		case "algorithm":
			oldZSKID = r.OldZSKID
		}
		if oldZSKID != 0 {
			if oldZSK, err := keyGen.LoadPublicKeyByID(domain, "zsk", oldZSKID); err == nil && oldZSK != nil {
				signingZSKs = append(signingZSKs, oldZSK)
			}
		}
	}

	// Run checks. The serial the world should see is the published one
	// (differs from the unsigned serial under serial_policy = "epoch").
	localSerial := zoneState.Serial
	if zoneState.PublishedSerial != 0 {
		localSerial = zoneState.PublishedSerial
	}
	result.DSCheck = v.CheckDSAtParent(domain, acceptableKSKs, kskUnloadable)
	result.DNSKEYCheck = v.checkDNSKEYVisible(domain, localKSKTag, localZSKTag, localKSK, localZSK)
	result.RRSIGCheck = v.checkRRSIGPresent(domain, localKSKTag, localZSKTag, signingKSKs, signingZSKs)
	result.SOACheck = v.checkSOASerial(domain, localSerial)

	// Compute overall status
	result.Overall = computeOverall(
		result.DSCheck.Status,
		result.DNSKEYCheck.Status,
		result.RRSIGCheck.Status,
		result.SOACheck.Status,
	)

	// Override: if the authoritative NS is unreachable, the zone is broken
	// regardless of whether DS exists at the parent — validating resolvers will
	// SERVFAIL every query to this zone. But an all-error state looks identical
	// when it's OUR local resolver that is down, which is a validator-side
	// problem, not a zone failure. Probe the resolver to tell them apart so we
	// don't mislabel a resolver outage as a bogus zone (R-049).
	if result.DNSKEYCheck.Status == "error" &&
		result.RRSIGCheck.Status == "error" &&
		result.SOACheck.Status == "error" {
		if v.resolverReachable() {
			result.Overall = "fail"
			result.Servfail = true
		} else {
			result.Overall = "error"
			result.ResolverOutage = true
			result.Errors = append(result.Errors,
				"all checks errored and the local resolver did not respond — this is likely a validator-side resolver problem, not a zone failure")
		}
	}

	// Override: a zone whose parent publishes a DS (so resolvers WILL try to
	// validate it) but whose chain is proven broken — mismatching DS, missing
	// or unverifiable keys, a required signature missing, expired or invalid
	// — is bogus/SERVFAIL, not "partial" (R-048, RA6X-032). Uncertainty
	// (errors) and the refresh-window notice stay partial.
	if bogusWhenDSPresent(result.DSCheck, result.DNSKEYCheck, result.RRSIGCheck) {
		result.Overall = "fail"
		result.Servfail = true
	}

	return result
}

// bogusWhenDSPresent downgrades the overall verdict to "fail" when the parent
// publishes a DS (the zone is meant to validate) but the DNSKEY or RRSIG check
// failed — a SERVFAIL/bogus condition that must not read as "partial" (R-048).
func bogusWhenDSPresent(ds DSCheckResult, dnskey DNSKEYCheckResult, rrsig RRSIGCheckResult) bool {
	if !ds.Found {
		return false
	}
	if ds.Status == "fail" && !ds.MatchesKSK {
		return true // the parent's DS authenticates none of our keys
	}
	if dnskey.Status == "fail" {
		return true
	}
	return rrsig.Status == "fail" || rrsig.Broken
}

// CheckDSAtParent queries the parent zone for DS records and compares them to the local KSK.
func (v *Validator) CheckDSAtParent(domain string, acceptableKSKs []*dns.DNSKEY, kskUnloadable bool) DSCheckResult {
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

	return evaluateDSMatch(result, dsRecords, acceptableKSKs, kskUnloadable)
}

// evaluateDSMatch is the pure DS-comparison core (R-045/046/047): it matches the
// parent's DS records against every acceptable KSK's DS in BOTH SHA-256 and
// SHA-384 (so a parent holding either digest — or, mid-rollover, only the old
// KSK's DS — still matches), and refuses to fail open to "pass" when the local
// KSK could not be loaded. The `result` carries ParentNS/DSRecords already set.
func evaluateDSMatch(result DSCheckResult, dsRecords []*dns.DS, acceptableKSKs []*dns.DNSKEY, kskUnloadable bool) DSCheckResult {
	var expected []*dns.DS
	for _, ksk := range acceptableKSKs {
		if ksk == nil {
			continue
		}
		for _, dt := range []uint8{dns.SHA256, dns.SHA384} {
			if ds := ksk.ToDS(dt); ds != nil {
				expected = append(expected, ds)
				result.ExpectedDS = append(result.ExpectedDS, ds.String())
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

	// No usable local key to compare against.
	if len(expected) == 0 {
		if kskUnloadable {
			// R-047: a DS exists at the parent but we can't load the local KSK to
			// verify it — do not fail open to "pass"; a stale/foreign DS would read
			// as healthy.
			result.Status = "error"
			result.Details = fmt.Sprintf("%d DS record(s) at parent but the local KSK could not be loaded for comparison", len(dsRecords))
		} else {
			result.Status = "pass"
			result.Details = fmt.Sprintf("%d DS record(s) found (no local KSK to compare)", len(dsRecords))
		}
		return result
	}

	// Match parent DS against any acceptable KSK's DS (any digest).
	var matchedTag uint16
	for _, ds := range dsRecords {
		for _, exp := range expected {
			if ds.KeyTag == exp.KeyTag &&
				ds.Algorithm == exp.Algorithm &&
				ds.DigestType == exp.DigestType &&
				strings.EqualFold(ds.Digest, exp.Digest) {
				result.MatchesKSK = true
				matchedTag = exp.KeyTag
				break
			}
		}
		if result.MatchesKSK {
			break
		}
	}
	if result.MatchesKSK {
		result.Status = "pass"
		result.Details = fmt.Sprintf("DS at parent matches local KSK (tag %d)", matchedTag)
	} else {
		result.Status = "fail"
		result.Details = "DS records found at parent but none match the local KSK(s)"
	}

	return result
}

// checkDNSKEYVisible queries the zone's authoritative NS for DNSKEY records.
func (v *Validator) checkDNSKEYVisible(domain string, kskTag, zskTag uint16, localKSK, localZSK *dns.DNSKEY) DNSKEYCheckResult {
	result := DNSKEYCheckResult{Status: "error", MaterialMatched: localKSK != nil || localZSK != nil}

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

	// A served key counts as ours only when its complete material matches
	// the local key (owner, flags, algorithm, public key); a key that merely
	// shares the 16-bit tag is a different key (RA6X-032). Tags are the
	// fallback only when no local key material could be loaded.
	for _, rr := range msg.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			tag := dnskey.KeyTag()
			result.KeyTags = append(result.KeyTags, tag)
			if localKSK != nil {
				if sameKeyMaterial(dnskey, localKSK) {
					result.KSKFound = true
				}
			} else if tag == kskTag {
				result.KSKFound = true
			}
			if localZSK != nil {
				if sameKeyMaterial(dnskey, localZSK) {
					result.ZSKFound = true
				}
			} else if tag == zskTag {
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
// rrsigEval summarizes the RRSIGs covering one RRset in an answer.
type rrsigEval struct {
	present    bool      // an RRSIG covering the type by an expected key exists at all
	valid      bool      // ...and one verifies cryptographically over the served RRset inside its validity window
	expired    bool      // present, verifying, but ALL out of window (expired or not-yet-valid)
	broken     bool      // present and in window, but none verifies over the served RRset
	validExp   time.Time // expiration of the valid signature found (when valid)
	expiredExp time.Time // earliest expiration among out-of-window sigs (for messaging)
}

// sameKeyMaterial reports whether two DNSKEYs are the same key: same owner,
// flags, protocol, algorithm and public key.
func sameKeyMaterial(a, b *dns.DNSKEY) bool {
	return a != nil && b != nil &&
		dns.CanonicalName(a.Hdr.Name) == dns.CanonicalName(b.Hdr.Name) &&
		a.Flags == b.Flags && a.Protocol == b.Protocol && a.Algorithm == b.Algorithm &&
		a.PublicKey == b.PublicKey
}

// evalRRSIGCover inspects the RRSIGs covering `covered` at the RRset's owner
// in an answer and verifies them cryptographically over the served RRset
// (RA6X-032). Only signatures by one of `keys` (complete key material) are
// considered; callers without local keys pass the served DNSKEY RRset. A
// signature counts as valid only when it is temporally in window (RFC 1982
// arithmetic via ValidityPeriod), its owner and signer name are the RRset's
// owner, and Verify succeeds over the complete served RRset — so an expired,
// foreign, corrupt or empty signature never reads as "signed" (R-012).
func evalRRSIGCover(answer []dns.RR, covered uint16, keys []*dns.DNSKEY, now time.Time) rrsigEval {
	var e rrsigEval
	// The served RRset, bound to one owner.
	var rrset []dns.RR
	var owner string
	for _, rr := range answer {
		if rr.Header().Rrtype != covered {
			continue
		}
		if owner == "" {
			owner = dns.CanonicalName(rr.Header().Name)
		}
		if dns.CanonicalName(rr.Header().Name) != owner {
			continue
		}
		rrset = append(rrset, rr)
	}
	if len(rrset) == 0 {
		return e
	}
	for _, rr := range answer {
		rrsig, ok := rr.(*dns.RRSIG)
		if !ok || rrsig.TypeCovered != covered {
			continue
		}
		if dns.CanonicalName(rrsig.Hdr.Name) != owner || dns.CanonicalName(rrsig.SignerName) != owner {
			continue // a signature over another owner or from another signer is not this RRset's
		}
		var key *dns.DNSKEY
		for _, k := range keys {
			if k != nil && k.KeyTag() == rrsig.KeyTag && k.Algorithm == rrsig.Algorithm {
				key = k
				break
			}
		}
		if key == nil {
			continue // signed by a key we don't recognize as this zone's — don't count it
		}
		e.present = true
		exp := time.Unix(int64(rrsig.Expiration), 0).UTC()
		if !rrsig.ValidityPeriod(now) {
			if !e.valid {
				e.expired = true
				if e.expiredExp.IsZero() || exp.Before(e.expiredExp) {
					e.expiredExp = exp
				}
			}
			continue
		}
		if err := rrsig.Verify(key, rrset); err != nil {
			if !e.valid {
				e.broken = true
			}
			continue
		}
		e.valid = true
		e.validExp = exp
		// RFC 4035 §5.3.3: resolvers accept an RRset when ANY one of its
		// RRSIGs validates, so a valid signature supersedes any expired or
		// broken one seen earlier in the answer — keep the documented
		// invariant that expired/broken mean "ALL signatures" regardless of
		// RR order.
		e.expired = false
		e.broken = false
		e.expiredExp = time.Time{}
		return e
	}
	return e
}

func (v *Validator) checkRRSIGPresent(domain string, kskTag, zskTag uint16, kskKeys, zskKeys []*dns.DNSKEY) RRSIGCheckResult {
	result := RRSIGCheckResult{Status: "error"}
	_, _ = kskTag, zskTag

	authNS, err := v.resolveNS(dns.Fqdn(domain))
	if err != nil {
		result.Details = fmt.Sprintf("failed to resolve NS for %s: %v", domain, err)
		return result
	}

	now := time.Now()

	// SOA is signed by the ZSK; DNSKEY by the KSK.
	soaMsg, err := queryDirect(authNS, dns.Fqdn(domain), dns.TypeSOA, v.timeout)
	if err != nil {
		result.Details = fmt.Sprintf("SOA query to %s failed: %v", authNS, err)
		return result
	}
	dnskeyMsg, err := queryDirect(authNS, dns.Fqdn(domain), dns.TypeDNSKEY, v.timeout)
	if err != nil {
		result.Details = fmt.Sprintf("DNSKEY query to %s failed: %v", authNS, err)
		return result
	}

	// Signatures are verified with the local key material for each role.
	// Without local keys the served DNSKEY RRset is the only key source; the
	// result then proves consistency of what is served, not that it is ours.
	if len(kskKeys) == 0 || len(zskKeys) == 0 {
		var served []*dns.DNSKEY
		for _, rr := range dnskeyMsg.Answer {
			if k, ok := rr.(*dns.DNSKEY); ok {
				served = append(served, k)
			}
		}
		if len(kskKeys) == 0 {
			kskKeys = served
		}
		if len(zskKeys) == 0 {
			zskKeys = served
		}
	}
	result.Verified = true
	soa := evalRRSIGCover(soaMsg.Answer, dns.TypeSOA, zskKeys, now)
	dnskey := evalRRSIGCover(dnskeyMsg.Answer, dns.TypeDNSKEY, kskKeys, now)

	result.SOASigned = soa.valid
	result.DNSKEYSigned = dnskey.valid

	// An out-of-window or non-verifying RRSIG is a hard fail naming the
	// cause, not a silent pass; a missing required signature is a proven
	// defect too (Broken) even though one of the two RRsets validates.
	switch {
	case soa.broken || dnskey.broken:
		result.Status = "fail"
		result.Broken = true
		which := "SOA"
		if !soa.broken {
			which = "DNSKEY"
		}
		result.Details = fmt.Sprintf("RRSIG over %s is present and in window but does not verify against the served RRset and expected key; resolvers will SERVFAIL", which)
	case soa.expired || dnskey.expired:
		result.Status = "fail"
		result.Broken = true
		exp := soa.expiredExp
		if exp.IsZero() || (!dnskey.expiredExp.IsZero() && dnskey.expiredExp.Before(exp)) {
			exp = dnskey.expiredExp
		}
		result.Details = fmt.Sprintf("RRSIG present but outside its validity window (expired %s); resolvers will SERVFAIL", exp.Format(time.RFC3339))
	case soa.valid && dnskey.valid:
		// Both valid — flag as "partial" (approaching expiry) when either is
		// within the configured refresh window, else pass.
		refresh := v.cfg.DNSSEC.SignatureRefresh.Duration
		soonest := soa.validExp
		if soonest.IsZero() || (!dnskey.validExp.IsZero() && dnskey.validExp.Before(soonest)) {
			soonest = dnskey.validExp
		}
		if refresh > 0 && !soonest.IsZero() && soonest.Sub(now) < refresh {
			result.Status = "partial"
			result.Details = fmt.Sprintf("RRSIG valid but within the refresh window (expires %s)", soonest.Format(time.RFC3339))
		} else {
			result.Status = "pass"
			result.Details = "valid RRSIG found for both SOA and DNSKEY"
		}
	case soa.valid || dnskey.valid:
		result.Status = "partial"
		result.Broken = true // one required signature is missing: with a DS at the parent this is bogus
		missing := "DNSKEY"
		if !soa.valid {
			missing = "SOA"
		}
		result.Details = fmt.Sprintf("valid RRSIG missing for %s", missing)
	default:
		result.Status = "fail"
		result.Broken = true
		result.Details = "no valid RRSIG records found for SOA or DNSKEY"
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

	// Try to resolve each NS to an address — IPv4 first, then IPv6 so
	// IPv6-only nameservers can still be validated.
	for _, nsName := range nsNames {
		// Check additional section (glue) first. DNS names are case-insensitive
		// (RFC 4034 §6.1), so compare canonically — a server that preserves the
		// original case in glue would otherwise miss this fast path (R-051).
		for _, rr := range r.Extra {
			switch addr := rr.(type) {
			case *dns.A:
				if dns.CanonicalName(addr.Hdr.Name) == dns.CanonicalName(nsName) {
					return net.JoinHostPort(addr.A.String(), v.portOr()), nil
				}
			case *dns.AAAA:
				if dns.CanonicalName(addr.Hdr.Name) == dns.CanonicalName(nsName) {
					return net.JoinHostPort(addr.AAAA.String(), v.portOr()), nil
				}
			}
		}

		// Fall back to resolving the NS hostname
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			am := new(dns.Msg)
			am.SetQuestion(dns.Fqdn(nsName), qtype)
			am.RecursionDesired = true

			ar, _, err := c.Exchange(am, resolver)
			if err != nil {
				continue
			}
			for _, rr := range ar.Answer {
				switch addr := rr.(type) {
				case *dns.A:
					return net.JoinHostPort(addr.A.String(), v.portOr()), nil
				case *dns.AAAA:
					return net.JoinHostPort(addr.AAAA.String(), v.portOr()), nil
				}
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

// resolverReachable does a lightweight sanity query (root NS, RD=1) against the
// configured resolver to distinguish a local-resolver outage from an
// authoritative-side failure (R-049). Any answer at all (even SERVFAIL) means
// the resolver is up; a transport error means it is not.
func (v *Validator) resolverReachable() bool {
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeNS)
	m.RecursionDesired = true
	c := new(dns.Client)
	c.Timeout = v.timeout
	_, _, err := c.Exchange(m, v.resolverAddr())
	return err == nil
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

	// A large DNSKEY/RRSIG answer can exceed the UDP buffer; on TC=1 the server
	// signals "retry over TCP". Without this we'd silently lose records and the
	// downstream checks would misreport (R-050).
	if r.Truncated {
		c.Net = "tcp"
		r, _, err = c.Exchange(m, server)
		if err != nil {
			return nil, err
		}
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
