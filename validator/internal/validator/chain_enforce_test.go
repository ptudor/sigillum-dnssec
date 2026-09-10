package validator

import (
	"crypto"
	"testing"
	"time"

	miekgdns "github.com/miekg/dns"
	dnspkg "github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// genTestDNSKEY generates a fresh ECDSA P-256 key for zone with the given flags and
// returns the miekg DNSKEY (for signing/RRset assembly), a crypto.Signer, and the
// validator-typed DNSKEYRecord a real response parse would have produced.
func genTestDNSKEY(t *testing.T, zone string, flags uint16) (*miekgdns.DNSKEY, crypto.Signer, dnspkg.DNSKEYRecord) {
	t.Helper()
	k := &miekgdns.DNSKEY{
		Hdr:       miekgdns.RR_Header{Name: zone, Rrtype: miekgdns.TypeDNSKEY, Class: miekgdns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: miekgdns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatal("generated key is not a crypto.Signer")
	}
	rec := dnspkg.DNSKEYRecord{
		Flags:     k.Flags,
		Protocol:  k.Protocol,
		Algorithm: k.Algorithm,
		PublicKey: k.PublicKey,
		KeyTag:    k.KeyTag(),
		IsKSK:     flags == 257,
		IsZSK:     flags == 256,
	}
	return k, signer, rec
}

// signDNSKEYRRset signs the DNSKEY RRset with signer/keyTag and returns the RRSIGRecord
// a real parse would produce.
func signDNSKEYRRset(t *testing.T, zone string, keys []*miekgdns.DNSKEY, signer crypto.Signer, keyTag uint16) dnspkg.RRSIGRecord {
	t.Helper()
	rrset := make([]miekgdns.RR, len(keys))
	for i, k := range keys {
		rrset[i] = k
	}
	inception := time.Now().Add(-time.Hour)
	expiration := time.Now().Add(24 * time.Hour)
	sig := &miekgdns.RRSIG{
		Hdr:         miekgdns.RR_Header{Name: zone, Rrtype: miekgdns.TypeRRSIG, Class: miekgdns.ClassINET, Ttl: 3600},
		TypeCovered: miekgdns.TypeDNSKEY,
		Algorithm:   miekgdns.ECDSAP256SHA256,
		Labels:      uint8(miekgdns.CountLabel(zone)),
		OrigTtl:     3600,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      keyTag,
		SignerName:  zone,
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("sign DNSKEY RRset: %v", err)
	}
	return dnspkg.RRSIGRecord{
		TypeCovered: 48,
		Algorithm:   sig.Algorithm,
		Labels:      sig.Labels,
		OriginalTTL: 3600,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		SignerName:  zone,
		Signature:   sig.Signature,
		IsValid:     true,
	}
}

func dsForKey(t *testing.T, zone string, key dnspkg.DNSKEYRecord) dnspkg.DSRecord {
	t.Helper()
	digest, err := ComputeDSDigestFromDNSKEY(zone, key, 2)
	if err != nil {
		t.Fatalf("compute DS digest: %v", err)
	}
	return dnspkg.DSRecord{KeyTag: key.KeyTag, Algorithm: key.Algorithm, DigestType: 2, Digest: digest}
}

// R-080: the DNSKEY RRset must be signed by a key the parent's DS authenticates. A rogue
// self-signed KSK added to the RRset (and signing the RRset) must be rejected even though
// the genuine DS-matched KSK is also present.
func TestVerifyDNSKEYRRSIGByKeys_RejectsRogueKSK(t *testing.T) {
	const zone = "example.com."
	kskA, signerA, recA := genTestDNSKEY(t, zone, 257) // genuine KSK (DS at parent)
	kskB, signerB, recB := genTestDNSKEY(t, zone, 257) // rogue KSK (attacker-added)
	zskC, _, recC := genTestDNSKEY(t, zone, 256)       // ZSK

	dnskeys := []dnspkg.DNSKEYRecord{recA, recB, recC}
	rrsetKeys := []*miekgdns.DNSKEY{kskA, kskB, zskC}

	dsA := dsForKey(t, zone, recA)
	authed := CollectDSMatchedKeys([]dnspkg.DSRecord{dsA}, dnskeys, zone)
	if len(authed) != 1 || authed[0].KeyTag != recA.KeyTag {
		t.Fatalf("CollectDSMatchedKeys should authenticate only KSK-A (tag %d), got %+v", recA.KeyTag, authed)
	}

	// Genuine: RRset signed by the DS-matched KSK-A verifies.
	rrsigA := signDNSKEYRRset(t, zone, rrsetKeys, signerA, recA.KeyTag)
	if err := VerifyDNSKEYRRSIGByKeys(zone, dnskeys, []dnspkg.RRSIGRecord{rrsigA}, authed); err != nil {
		t.Fatalf("genuine DNSKEY RRSIG by DS-matched KSK must verify, got: %v", err)
	}

	// Attack: RRset signed by the rogue KSK-B, which is present in the RRset but is NOT
	// authenticated by the parent DS. Must be rejected (the R-080 chain break).
	rrsigB := signDNSKEYRRset(t, zone, rrsetKeys, signerB, recB.KeyTag)
	if err := VerifyDNSKEYRRSIGByKeys(zone, dnskeys, []dnspkg.RRSIGRecord{rrsigB}, authed); err == nil {
		t.Fatal("DNSKEY RRset signed by a rogue (non-DS-matched) KSK was accepted; R-080 not enforced")
	}
}

func TestVerifyDNSKEYRRSIGByKeys_NoAuthenticatedKeys(t *testing.T) {
	const zone = "example.com."
	kskA, signerA, recA := genTestDNSKEY(t, zone, 257)
	rrsigA := signDNSKEYRRset(t, zone, []*miekgdns.DNSKEY{kskA}, signerA, recA.KeyTag)

	// Empty authenticated set: nothing the parent vouches for, so the RRset cannot be
	// trusted regardless of its self-signature.
	if err := VerifyDNSKEYRRSIGByKeys(zone, []dnspkg.DNSKEYRecord{recA}, []dnspkg.RRSIGRecord{rrsigA}, nil); err == nil {
		t.Fatal("expected error when no authenticated keys are available")
	}
}

func TestCollectDSMatchedKeys(t *testing.T) {
	const zone = "example.com."
	_, _, recA := genTestDNSKEY(t, zone, 257)
	_, _, recB := genTestDNSKEY(t, zone, 257)
	dnskeys := []dnspkg.DNSKEYRecord{recA, recB}

	// A DS with the right key tag but a wrong digest must NOT authenticate the key.
	wrongDigestDS := dnspkg.DSRecord{KeyTag: recA.KeyTag, Algorithm: recA.Algorithm, DigestType: 2, Digest: "DEADBEEF"}
	if got := CollectDSMatchedKeys([]dnspkg.DSRecord{wrongDigestDS}, dnskeys, zone); len(got) != 0 {
		t.Fatalf("a DS with a mismatched digest must not authenticate any key, got %d", len(got))
	}

	// The correct DS authenticates exactly its key.
	dsA := dsForKey(t, zone, recA)
	got := CollectDSMatchedKeys([]dnspkg.DSRecord{dsA}, dnskeys, zone)
	if len(got) != 1 || got[0].KeyTag != recA.KeyTag {
		t.Fatalf("expected only KSK-A authenticated, got %+v", got)
	}
}

// buildDSAbsenceResponse builds a parent QueryResult whose authority section is an NSEC
// at the delegation point (child) signed by a fresh parent ZSK, plus that ZSK record.
// bitmap is the served/signed NSEC type bitmap (e.g. NS+RRSIG for an insecure delegation,
// or NS+DS+RRSIG for a secure one).
func buildDSAbsenceResponse(t *testing.T, child, parentZone string, bitmap []uint16) (*dnspkg.QueryResult, dnspkg.DNSKEYRecord) {
	t.Helper()
	const ttl = 300

	dnskey := &miekgdns.DNSKEY{
		Hdr:       miekgdns.RR_Header{Name: parentZone, Rrtype: miekgdns.TypeDNSKEY, Class: miekgdns.ClassINET, Ttl: ttl},
		Flags:     256,
		Protocol:  3,
		Algorithm: miekgdns.ECDSAP256SHA256,
	}
	priv, err := dnskey.Generate(256)
	if err != nil {
		t.Fatalf("generate parent key: %v", err)
	}
	signer := priv.(crypto.Signer)

	nsec := &miekgdns.NSEC{
		Hdr:        miekgdns.RR_Header{Name: child, Rrtype: miekgdns.TypeNSEC, Class: miekgdns.ClassINET, Ttl: ttl},
		NextDomain: parentZone,
		TypeBitMap: bitmap,
	}
	inception := time.Now().Add(-time.Hour)
	expiration := time.Now().Add(24 * time.Hour)
	sig := &miekgdns.RRSIG{
		Hdr:         miekgdns.RR_Header{Name: child, Rrtype: miekgdns.TypeRRSIG, Class: miekgdns.ClassINET, Ttl: ttl},
		TypeCovered: miekgdns.TypeNSEC,
		Algorithm:   miekgdns.ECDSAP256SHA256,
		Labels:      uint8(miekgdns.CountLabel(child)),
		OrigTtl:     ttl,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      dnskey.KeyTag(),
		SignerName:  parentZone,
	}
	if err := sig.Sign(signer, []miekgdns.RR{nsec}); err != nil {
		t.Fatalf("sign NSEC: %v", err)
	}

	msg := new(miekgdns.Msg)
	msg.SetQuestion(child, miekgdns.TypeDS)
	msg.Rcode = miekgdns.RcodeSuccess
	msg.Ns = []miekgdns.RR{nsec, sig}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}

	bm := make([]string, 0, len(bitmap))
	for _, tt := range bitmap {
		bm = append(bm, dnspkg.TypeName(tt))
	}
	qr := &dnspkg.QueryResult{
		RCode:       miekgdns.RcodeSuccess,
		NSEC:        []dnspkg.NSECRecord{{Owner: child, NextDomain: parentZone, TypeBitmap: bm}},
		RawResponse: raw,
	}
	key := dnspkg.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: dnskey.Algorithm,
		PublicKey: dnskey.PublicKey,
		KeyTag:    dnskey.KeyTag(),
		IsZSK:     true,
	}
	return qr, key
}

// R-081: an insecure delegation may only be declared on an authenticated proof that the
// DS RRset is absent. A stripped DS (no NSEC at all) must not read as insecure, and an
// NSEC that carries the DS bit contradicts the "no DS" claim.
func TestVerifyDSAbsence(t *testing.T) {
	v := &Validator{}
	const parentZone = "example.com."
	const child = "sub.example.com."

	// Genuine insecure delegation: NSEC with NS set, DS clear, signed by the parent.
	qr, parentKey := buildDSAbsenceResponse(t, child, parentZone,
		[]uint16{miekgdns.TypeNS, miekgdns.TypeRRSIG})
	if _, ok := v.verifyDSAbsence(child, parentZone, []dnspkg.DNSKEYRecord{parentKey}, qr); !ok {
		t.Fatal("a signed NSEC proving no DS must verify as an insecure delegation")
	}

	// DS bit present: the NSEC contradicts the empty-DS answer → not a valid absence proof.
	qrDS, keyDS := buildDSAbsenceResponse(t, child, parentZone,
		[]uint16{miekgdns.TypeNS, miekgdns.TypeDS, miekgdns.TypeRRSIG})
	if _, ok := v.verifyDSAbsence(child, parentZone, []dnspkg.DNSKEYRecord{keyDS}, qrDS); ok {
		t.Fatal("an NSEC with the DS bit set must not prove DS absence")
	}

	// No NSEC/NSEC3 at all (DS stripped by an attacker) → cannot prove insecure.
	empty := &dnspkg.QueryResult{RCode: miekgdns.RcodeSuccess}
	if _, ok := v.verifyDSAbsence(child, parentZone, []dnspkg.DNSKEYRecord{parentKey}, empty); ok {
		t.Fatal("an empty response must not prove an insecure delegation")
	}

	// Wrong parent key: the NSEC RRSIG cannot be verified → fail closed.
	_, _, otherKey := genTestDNSKEY(t, parentZone, 256)
	if _, ok := v.verifyDSAbsence(child, parentZone, []dnspkg.DNSKEYRecord{otherKey}, qr); ok {
		t.Fatal("DS-absence proof must fail when the NSEC RRSIG does not verify")
	}
}

func TestFinalizeNoDSDelegation(t *testing.T) {
	v := &Validator{}
	const parentZone = "example.com."
	const child = "sub.example.com."

	// Insecure parent (no authenticated DNSKEY threaded in): unsigned delegation is
	// genuinely insecure and needs no proof.
	r1 := NewZoneResult(child)
	v.finalizeNoDSDelegation(r1, child, parentZone, nil, nil)
	if r1.Status != StatusInsecure {
		t.Fatalf("no parent DNSKEY should yield insecure, got %s", r1.Status)
	}

	// Secure parent, valid absence proof → insecure.
	qr, parentKey := buildDSAbsenceResponse(t, child, parentZone,
		[]uint16{miekgdns.TypeNS, miekgdns.TypeRRSIG})
	r2 := NewZoneResult(child)
	v.finalizeNoDSDelegation(r2, child, parentZone, []dnspkg.DNSKEYRecord{parentKey}, &parentDSResult{Response: qr})
	if r2.Status != StatusInsecure {
		t.Fatalf("valid absence proof should yield insecure, got %s", r2.Status)
	}

	// Secure parent, no denial at all → indeterminate (possible downgrade), not insecure.
	r3 := NewZoneResult(child)
	v.finalizeNoDSDelegation(r3, child, parentZone, []dnspkg.DNSKEYRecord{parentKey}, &parentDSResult{Response: &dnspkg.QueryResult{}})
	if r3.Status != StatusIndeterminate {
		t.Fatalf("missing absence proof should yield indeterminate, got %s", r3.Status)
	}

	// Secure parent, contradictory NSEC (DS bit set) → bogus.
	qrDS, keyDS := buildDSAbsenceResponse(t, child, parentZone,
		[]uint16{miekgdns.TypeNS, miekgdns.TypeDS, miekgdns.TypeRRSIG})
	r4 := NewZoneResult(child)
	v.finalizeNoDSDelegation(r4, child, parentZone, []dnspkg.DNSKEYRecord{keyDS}, &parentDSResult{Response: qrDS})
	if r4.Status != StatusBogus {
		t.Fatalf("a DS-bit NSEC should yield bogus, got %s", r4.Status)
	}
}

// R-082: the leaf record's signature outcome must move the overall verdict.
func TestRecordValidationVerdict(t *testing.T) {
	tests := []struct {
		name string
		rv   *RecordValidation
		want ValidationStatus
	}{
		{"nil stays secure", nil, StatusSecure},
		{"verified answer secure", &RecordValidation{RRSIGVerified: true}, StatusSecure},
		// R-026: a wildcard answer whose data RRSIG verified but whose no-exact-match
		// proof did not verify is bogus, not secure.
		{"wildcard without verified proof is bogus", &RecordValidation{RRSIGVerified: true, Wildcard: true, Error: "wildcard answer lacks proof"}, StatusBogus},
		{"wildcard with verified proof secure", &RecordValidation{RRSIGVerified: true, Wildcard: true, WildcardProofVerified: true}, StatusSecure},
		{"expired signature bogus", &RecordValidation{Error: "A record RRSIG expired at 2020-01-01T00:00:00Z"}, StatusBogus},
		{"forged signature bogus", &RecordValidation{Error: "A record RRSIG cryptographic verification failed: bad"}, StatusBogus},
		{"missing rrsig bogus", &RecordValidation{Error: "no RRSIG for A record"}, StatusBogus},
		{"unqueryable answer indeterminate", &RecordValidation{Error: "failed to query A record from authoritative servers"}, StatusIndeterminate},
		{"nameserver failure indeterminate", &RecordValidation{Error: "failed to resolve nameservers: timeout"}, StatusIndeterminate},
		{"unverified denial bogus", &RecordValidation{DenialProof: &NSECProof{Verified: false, Error: "incomplete"}}, StatusBogus},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := recordValidationVerdict(tt.rv)
			if got != tt.want {
				t.Errorf("recordValidationVerdict = %s, want %s", got, tt.want)
			}
		})
	}
}

// R-079 relies on the DS RRset itself being cryptographically verified before a secure
// verdict. Confirm the mechanism: a genuine DS RRSIG verifies; a forged one does not.
func TestDSRRSIGEnforcementMechanism(t *testing.T) {
	const zone = "sub.example.com."
	const parentZone = "example.com."

	parentKey, signer, parentRec := genTestDNSKEY(t, parentZone, 256)
	ds := dnpkgDS(t, zone)

	inception := time.Now().Add(-time.Hour)
	expiration := time.Now().Add(24 * time.Hour)
	sig := &miekgdns.RRSIG{
		Hdr:         miekgdns.RR_Header{Name: zone, Rrtype: miekgdns.TypeRRSIG, Class: miekgdns.ClassINET, Ttl: 3600},
		TypeCovered: miekgdns.TypeDS,
		Algorithm:   miekgdns.ECDSAP256SHA256,
		Labels:      uint8(miekgdns.CountLabel(zone)),
		OrigTtl:     3600,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      parentKey.KeyTag(),
		SignerName:  parentZone,
	}
	if err := sig.Sign(signer, []miekgdns.RR{ds}); err != nil {
		t.Fatalf("sign DS: %v", err)
	}

	msg := new(miekgdns.Msg)
	msg.SetQuestion(zone, miekgdns.TypeDS)
	msg.Answer = []miekgdns.RR{ds, sig}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	// Genuine DS RRSIG verifies against the parent key.
	if _, err := VerifyRRsetRRSIGFromResponse(raw, miekgdns.TypeDS, parentRec, parentKey.KeyTag(), zone, true); err != nil {
		t.Fatalf("genuine DS RRSIG must verify: %v", err)
	}

	// A different (rogue) parent key cannot verify it — this is what R-079 gates on.
	_, _, rogueRec := genTestDNSKEY(t, parentZone, 256)
	if _, err := VerifyRRsetRRSIGFromResponse(raw, miekgdns.TypeDS, rogueRec, rogueRec.KeyTag, zone, true); err == nil {
		t.Fatal("DS RRSIG must not verify against a key that did not sign it")
	}
}

// dnpkgDS returns a miekg DS record for the given child zone (content is irrelevant to
// the RRSIG mechanics being tested).
func dnpkgDS(t *testing.T, zone string) *miekgdns.DS {
	t.Helper()
	return &miekgdns.DS{
		Hdr:        miekgdns.RR_Header{Name: zone, Rrtype: miekgdns.TypeDS, Class: miekgdns.ClassINET, Ttl: 3600},
		KeyTag:     12345,
		Algorithm:  miekgdns.ECDSAP256SHA256,
		DigestType: 2,
		Digest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}
