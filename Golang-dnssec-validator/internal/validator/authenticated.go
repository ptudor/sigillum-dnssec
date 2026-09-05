package validator

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// VerifiedRRset is the exact RRset and the exact RRSIG that verified it under
// a trusted key. It is the only object that may be promoted to authenticated
// data: chain construction, denial reasoning and wildcard/owner/signer/timing
// decisions must read from here, never from the merged display slices that a
// parsed QueryResult carries for diagnostics (RA6X-007, RA6X-009, RA6X-016).
type VerifiedRRset struct {
	Owner     string     // canonical owner name of the RRset
	Type      uint16     // RR type of the RRset
	Records   []dns.RR   // the exact wire records that were signed
	Signature *dns.RRSIG // the exact RRSIG that verified
	Key       dnspkg.DNSKEYRecord
}

// SignerName returns the canonical signer name of the signature that verified.
func (v *VerifiedRRset) SignerName() string {
	return dns.CanonicalName(v.Signature.SignerName)
}

// Labels returns the authenticated RRSIG Labels field.
func (v *VerifiedRRset) Labels() uint8 {
	return v.Signature.Labels
}

// VerifyRRsetFromResponse performs full cryptographic verification of one RRset
// of typeCovered in a raw DNS response and returns the exact records and the
// exact signature that verified.
//
// Every covering RRSIG is evaluated as an indivisible candidate: its owner,
// signer name, validity window and cryptographic check must all hold for that
// one signature before the RRset it covers is returned (RA6X-009). Each
// candidate is verified against every trusted key sharing its key tag that is
// eligible to sign (R-043/R-044). When expectedOwner is non-empty the signed
// RRset must be owned by that name; when expectedSigner is non-empty the
// signature's Signer's Name must be that zone (RA6X-007/016); when answerOnly
// is true only the Answer section is considered, so a valid RRset replayed in
// Authority/Additional cannot authenticate the queried name (R-027).
func VerifyRRsetFromResponse(rawResponse []byte, typeCovered uint16, keys []dnspkg.DNSKEYRecord, expectedOwner, expectedSigner string, answerOnly bool) (*VerifiedRRset, error) {
	return verifyRRsetFromResponseB(nil, rawResponse, typeCovered, keys, expectedOwner, expectedSigner, answerOnly)
}

// verifyRRsetFromResponseB is VerifyRRsetFromResponse charged against a
// validation's work budget (nil = unbounded) (RA6X-052).
func verifyRRsetFromResponseB(b *VerifyBudget, rawResponse []byte, typeCovered uint16, keys []dnspkg.DNSKEYRecord, expectedOwner, expectedSigner string, answerOnly bool) (*VerifiedRRset, error) {
	if len(rawResponse) == 0 {
		return nil, fmt.Errorf("raw DNS response unavailable")
	}
	var msg dns.Msg
	if err := msg.Unpack(rawResponse); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}
	var scan []dns.RR
	if answerOnly {
		scan = msg.Answer
	} else {
		scan = append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...)
	}
	return verifyRRsetInRecords(b, scan, typeCovered, keys, expectedOwner, expectedSigner)
}

// dedupeKeys drops keys with identical material (owner, flags, protocol,
// algorithm, public key): repeated records must not multiply crypto work.
func dedupeKeys(keys []dnspkg.DNSKEYRecord) []dnspkg.DNSKEYRecord {
	seen := make(map[string]bool, len(keys))
	out := make([]dnspkg.DNSKEYRecord, 0, len(keys))
	for _, k := range keys {
		id := fmt.Sprintf("%s/%d/%d/%d/%s", dns.CanonicalName(k.Owner), k.Flags, k.Protocol, k.Algorithm, k.PublicKey)
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, k)
	}
	return out
}

// verifyRRsetInRecords is VerifyRRsetFromResponse over already-unpacked records.
// Every signature verification attempt is charged to b; identical signatures
// and identical keys are collapsed first, and algorithm/tag/eligibility
// filtering happens before any cryptography (RA6X-052).
func verifyRRsetInRecords(b *VerifyBudget, scan []dns.RR, typeCovered uint16, keys []dnspkg.DNSKEYRecord, expectedOwner, expectedSigner string) (*VerifiedRRset, error) {
	wantOwner := ""
	if expectedOwner != "" {
		wantOwner = dns.CanonicalName(expectedOwner)
	}
	wantSigner := ""
	if expectedSigner != "" {
		wantSigner = dns.CanonicalName(expectedSigner)
	}

	rrsetByOwner := make(map[string][]dns.RR)
	candidates := make([]*dns.RRSIG, 0)
	seenSig := make(map[string]bool)
	for _, rr := range scan {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == typeCovered {
				id := dns.CanonicalName(v.Hdr.Name) + "/" + dns.CanonicalName(v.SignerName) + "/" + fmt.Sprint(v.KeyTag, v.Labels, v.Inception, v.Expiration) + "/" + v.Signature
				if seenSig[id] {
					continue
				}
				seenSig[id] = true
				candidates = append(candidates, v)
			}
		default:
			if rr.Header().Rrtype == typeCovered {
				owner := dns.CanonicalName(rr.Header().Name)
				rrsetByOwner[owner] = append(rrsetByOwner[owner], rr)
			}
		}
	}
	keys = dedupeKeys(keys)

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no RRSIG found in response covering type %s", dnspkg.TypeName(typeCovered))
	}

	var lastErr error
	for _, sig := range candidates {
		owner := dns.CanonicalName(sig.Hdr.Name)
		if wantOwner != "" && owner != wantOwner {
			lastErr = fmt.Errorf("RRSIG owner %s does not match queried owner %s", sig.Hdr.Name, expectedOwner)
			continue
		}
		if wantSigner != "" && dns.CanonicalName(sig.SignerName) != wantSigner {
			lastErr = fmt.Errorf("RRSIG signer %s is not the expected signing zone %s", sig.SignerName, expectedSigner)
			continue
		}
		rrset := rrsetByOwner[owner]
		if len(rrset) == 0 {
			lastErr = fmt.Errorf("no RRset found for owner %s and type %s", sig.Hdr.Name, dnspkg.TypeName(typeCovered))
			continue
		}
		// Bind the time check to THIS candidate before its crypto check (R-028).
		if !rrsigWireTimeValid(sig) {
			lastErr = fmt.Errorf("RRSIG (owner %s, key tag %d) outside its validity period (inception %s, expiration %s)",
				sig.Hdr.Name, sig.KeyTag,
				time.Unix(int64(sig.Inception), 0).UTC().Format(time.RFC3339),
				time.Unix(int64(sig.Expiration), 0).UTC().Format(time.RFC3339))
			continue
		}
		cands := EligibleKeysByKeyTag(sig.KeyTag, keys)
		if len(cands) == 0 {
			lastErr = fmt.Errorf("no eligible trusted key with tag %d for RRSIG over %s %s", sig.KeyTag, sig.Hdr.Name, dnspkg.TypeName(typeCovered))
			continue
		}
		for _, ck := range cands {
			if ck.Algorithm != sig.Algorithm {
				lastErr = fmt.Errorf("RRSIG algorithm %d does not match key %d algorithm %d", sig.Algorithm, ck.KeyTag, ck.Algorithm)
				continue
			}
			signingKey, err := trustedKeyForSigner(ck, sig.SignerName)
			if err != nil {
				lastErr = err
				continue
			}
			if err := b.charge(1); err != nil {
				return nil, err
			}
			if err := sig.Verify(signingKey, rrset); err != nil {
				lastErr = fmt.Errorf("cryptographic RRset verification failed: %w", err)
				continue
			}
			return &VerifiedRRset{
				Owner:     owner,
				Type:      typeCovered,
				Records:   rrset,
				Signature: sig,
				Key:       ck,
			}, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no verifiable RRSIG candidate for type %s", dnspkg.TypeName(typeCovered))
}

// trustedKeyForSigner rebuilds the wire DNSKEY for a trusted key so a signature
// naming signerName can be checked against it. A key that carries its own
// authenticated owner (parsed from the zone's verified DNSKEY RRset) is used at
// that owner and must be the signer's zone; a signature by another zone's key
// is rejected even when the same key material was reused there (RA6X-016). A
// key without an owner (constructed in-process) is placed at the signer name.
func trustedKeyForSigner(key dnspkg.DNSKEYRecord, signerName string) (*dns.DNSKEY, error) {
	zone := signerName
	if key.Owner != "" {
		if dns.CanonicalName(key.Owner) != dns.CanonicalName(signerName) {
			return nil, fmt.Errorf("trusted key (tag %d) belongs to zone %s, not signer %s", key.KeyTag, key.Owner, signerName)
		}
		zone = key.Owner
	}
	return reconstructDNSKEY(zone, key)
}

// VerifyDNSKEYRRsetFromResponse verifies the zone's own DNSKEY RRset in a raw
// DNSKEY response against the parent/anchor-authenticated keys and returns the
// exact verified RRset. Only the Answer-section DNSKEY RRset owned by zone is
// considered; a DNSKEY in Authority or Additional is never part of the RRset
// (RA6X-007). The signature must name zone as its signer and be produced by an
// authenticated key (RFC 4035 §5.2, R-080).
func VerifyDNSKEYRRsetFromResponse(rawResponse []byte, zone string, authenticatedKeys []dnspkg.DNSKEYRecord) (*VerifiedRRset, error) {
	return verifyDNSKEYRRsetFromResponseB(nil, rawResponse, zone, authenticatedKeys)
}

// verifyDNSKEYRRsetFromResponseB is VerifyDNSKEYRRsetFromResponse charged
// against a validation's work budget (RA6X-052).
func verifyDNSKEYRRsetFromResponseB(b *VerifyBudget, rawResponse []byte, zone string, authenticatedKeys []dnspkg.DNSKEYRecord) (*VerifiedRRset, error) {
	if len(authenticatedKeys) == 0 {
		return nil, fmt.Errorf("no parent-authenticated (DS/anchor-matched) key available to verify the DNSKEY RRset")
	}
	return verifyRRsetFromResponseB(b, rawResponse, dns.TypeDNSKEY, authenticatedKeys, zone, zone, true)
}

// VerifyDenialRRsetsFromResponse cryptographically verifies every NSEC/NSEC3
// RRset (typeCovered = 47 or 50) found in the Answer and Authority sections of
// a raw response and returns exactly those RRsets that verified under the
// supplied zone keys. Additional-section records are never candidates.
//
// Authenticated denial of existence (RFC 4035 §5.4, RFC 5155 §8) may only use
// records whose signatures verified; an RRset that does not verify is reported
// in rejected and excluded from the proof rather than either failing the whole
// response (an attacker could then inject junk to force a false Bogus) or
// being consumed unauthenticated (a false Secure). An error is returned when
// no RRset of the type verified. When expectedSigner is non-empty every
// accepted signature must name that zone as its signer (RA6X-016).
func VerifyDenialRRsetsFromResponse(rawResponse []byte, typeCovered uint16, keys []dnspkg.DNSKEYRecord, expectedSigner string) (verified []VerifiedRRset, rejected []string, err error) {
	return verifyDenialRRsetsFromResponseB(nil, rawResponse, typeCovered, keys, expectedSigner)
}

// verifyDenialRRsetsFromResponseB is VerifyDenialRRsetsFromResponse charged
// against a validation's work budget; an exhausted budget aborts the whole
// call rather than being reported as an unverifiable RRset (RA6X-052).
func verifyDenialRRsetsFromResponseB(b *VerifyBudget, rawResponse []byte, typeCovered uint16, keys []dnspkg.DNSKEYRecord, expectedSigner string) (verified []VerifiedRRset, rejected []string, err error) {
	if len(rawResponse) == 0 {
		return nil, nil, fmt.Errorf("raw DNS response unavailable")
	}
	var msg dns.Msg
	if err := msg.Unpack(rawResponse); err != nil {
		return nil, nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	scan := append(append([]dns.RR{}, msg.Answer...), msg.Ns...)
	rrsetByOwner := make(map[string][]dns.RR)
	sigsByOwner := make(map[string][]*dns.RRSIG)
	order := make([]string, 0)
	for _, rr := range scan {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == typeCovered {
				owner := dns.CanonicalName(v.Hdr.Name)
				sigsByOwner[owner] = append(sigsByOwner[owner], v)
			}
		default:
			if rr.Header().Rrtype == typeCovered {
				owner := dns.CanonicalName(rr.Header().Name)
				if _, seen := rrsetByOwner[owner]; !seen {
					order = append(order, owner)
				}
				rrsetByOwner[owner] = append(rrsetByOwner[owner], rr)
			}
		}
	}

	if len(rrsetByOwner) == 0 {
		return nil, nil, fmt.Errorf("no %s records found in the Answer or Authority section", dnspkg.TypeName(typeCovered))
	}

	wantZone := ""
	if expectedSigner != "" {
		wantZone = dns.CanonicalName(expectedSigner)
	}

	for _, owner := range order {
		rrset := rrsetByOwner[owner]
		sigs := sigsByOwner[owner]
		if len(sigs) == 0 {
			rejected = append(rejected, fmt.Sprintf("%s RRset at %s has no RRSIG", dnspkg.TypeName(typeCovered), owner))
			continue
		}
		// RA6X-016: a zone's denial records are owned inside that zone. A record
		// owned elsewhere is another zone's evidence even if the same key
		// material would verify it.
		if wantZone != "" && !dns.IsSubDomain(wantZone, owner) {
			rejected = append(rejected, fmt.Sprintf("%s RRset at %s is not within zone %s", dnspkg.TypeName(typeCovered), owner, expectedSigner))
			continue
		}
		records := append(append([]dns.RR{}, rrset...), rrsToRRs(sigs)...)
		v, verr := verifyRRsetInRecords(b, records, typeCovered, keys, owner, expectedSigner)
		if verr != nil {
			if IsBudgetExhausted(verr) {
				return nil, rejected, verr
			}
			rejected = append(rejected, fmt.Sprintf("%s RRset at %s: %v", dnspkg.TypeName(typeCovered), owner, verr))
			continue
		}
		verified = append(verified, *v)
	}

	if len(verified) == 0 {
		return nil, rejected, fmt.Errorf("no %s RRset verified: %s", dnspkg.TypeName(typeCovered), strings.Join(rejected, "; "))
	}
	return verified, rejected, nil
}

// rrsToRRs widens a slice of *dns.RRSIG to []dns.RR.
func rrsToRRs(sigs []*dns.RRSIG) []dns.RR {
	out := make([]dns.RR, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s)
	}
	return out
}

// nsecRecordsFromVerified converts verified NSEC RRsets into the validator's
// record type for the proof engine. Every returned record is authenticated.
func nsecRecordsFromVerified(verified []VerifiedRRset) []dnspkg.NSECRecord {
	out := make([]dnspkg.NSECRecord, 0)
	for _, v := range verified {
		for _, rr := range v.Records {
			if n, ok := rr.(*dns.NSEC); ok {
				out = append(out, dnspkg.NSECFromRR(n, dnspkg.SectionAuthority))
			}
		}
	}
	return out
}

// nsec3RecordsFromVerified converts verified NSEC3 RRsets into the validator's
// record type for the proof engine. Every returned record is authenticated.
func nsec3RecordsFromVerified(verified []VerifiedRRset) []dnspkg.NSEC3Record {
	out := make([]dnspkg.NSEC3Record, 0)
	for _, v := range verified {
		for _, rr := range v.Records {
			if n, ok := rr.(*dns.NSEC3); ok {
				out = append(out, dnspkg.NSEC3FromRR(n, dnspkg.SectionAuthority))
			}
		}
	}
	return out
}

// dsRecordsFromVerified converts the exact verified DS RRset into the
// validator's record type. Every returned record is authenticated.
func dsRecordsFromVerified(v *VerifiedRRset) []dnspkg.DSRecord {
	out := make([]dnspkg.DSRecord, 0, len(v.Records))
	for _, rr := range v.Records {
		if d, ok := rr.(*dns.DS); ok {
			out = append(out, dnspkg.DSFromRR(d, dnspkg.SectionAnswer))
		}
	}
	return out
}

// answerHasTypeAt reports whether the Answer section of a raw response holds
// at least one record of qtype owned by owner. A CNAME/DNAME chain answer
// carries the target's records at OTHER owners, so a section-wide type check
// cannot decide whether the queried name itself was answered (RA6X-014).
func answerHasTypeAt(rawResponse []byte, qtype uint16, owner string) bool {
	if len(rawResponse) == 0 {
		return false
	}
	var msg dns.Msg
	if err := msg.Unpack(rawResponse); err != nil {
		return false
	}
	want := dns.CanonicalName(owner)
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == qtype && dns.CanonicalName(rr.Header().Name) == want {
			return true
		}
	}
	return false
}

// answerDNSKEYsOwnedBy returns the parsed DNSKEY records that came from the
// Answer section and are owned by zone: the served DNSKEY RRset candidates.
// Keys in Authority/Additional or at another owner are diagnostics only.
func answerDNSKEYsOwnedBy(keys []dnspkg.DNSKEYRecord, zone string) []dnspkg.DNSKEYRecord {
	want := dns.CanonicalName(zone)
	out := make([]dnspkg.DNSKEYRecord, 0, len(keys))
	for _, k := range keys {
		if !dnspkg.InSection(k.Section, dnspkg.SectionAnswer) {
			continue
		}
		if k.Owner != "" && dns.CanonicalName(k.Owner) != want {
			continue
		}
		out = append(out, k)
	}
	return out
}

// answerDSOwnedBy returns the parsed DS records from the Answer section owned
// by child: the served DS RRset for the delegation. They are still unverified.
func answerDSOwnedBy(ds []dnspkg.DSRecord, child string) []dnspkg.DSRecord {
	want := dns.CanonicalName(child)
	out := make([]dnspkg.DSRecord, 0, len(ds))
	for _, d := range ds {
		if !dnspkg.InSection(d.Section, dnspkg.SectionAnswer) {
			continue
		}
		if d.Owner != "" && dns.CanonicalName(d.Owner) != want {
			continue
		}
		out = append(out, d)
	}
	return out
}

// answerRRSIGsOwnedBy returns the parsed RRSIG records from the Answer section
// whose signed RRset is owned by owner.
func answerRRSIGsOwnedBy(sigs []dnspkg.RRSIGRecord, owner string) []dnspkg.RRSIGRecord {
	want := dns.CanonicalName(owner)
	out := make([]dnspkg.RRSIGRecord, 0, len(sigs))
	for _, s := range sigs {
		if !dnspkg.InSection(s.Section, dnspkg.SectionAnswer) {
			continue
		}
		if s.Owner != "" && dns.CanonicalName(s.Owner) != want {
			continue
		}
		out = append(out, s)
	}
	return out
}

// answerCNAMEsOwnedBy returns the parsed CNAME records from the Answer section
// owned by owner.
func answerCNAMEsOwnedBy(cnames []dnspkg.CNAMERecord, owner string) []dnspkg.CNAMERecord {
	want := dns.CanonicalName(owner)
	out := make([]dnspkg.CNAMERecord, 0, len(cnames))
	for _, c := range cnames {
		if !dnspkg.InSection(c.Section, dnspkg.SectionAnswer) {
			continue
		}
		if c.Name != "" && dns.CanonicalName(c.Name) != want {
			continue
		}
		out = append(out, c)
	}
	return out
}

// denialNSECCandidates returns the parsed NSEC records that may take part in a
// denial proof: those from the Answer or Authority section. Additional-section
// records are never denial evidence.
func denialNSECCandidates(records []dnspkg.NSECRecord) []dnspkg.NSECRecord {
	out := make([]dnspkg.NSECRecord, 0, len(records))
	for _, r := range records {
		if dnspkg.InSection(r.Section, dnspkg.SectionAuthority, dnspkg.SectionAnswer) {
			out = append(out, r)
		}
	}
	return out
}

// denialNSEC3Candidates is denialNSECCandidates for NSEC3 records.
func denialNSEC3Candidates(records []dnspkg.NSEC3Record) []dnspkg.NSEC3Record {
	out := make([]dnspkg.NSEC3Record, 0, len(records))
	for _, r := range records {
		if dnspkg.InSection(r.Section, dnspkg.SectionAuthority, dnspkg.SectionAnswer) {
			out = append(out, r)
		}
	}
	return out
}
