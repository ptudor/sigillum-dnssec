package validator

import (
	"crypto"
	"strings"
	"testing"
	"time"

	miekgdns "github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// --- Item A: wildcard-synthesized positive answers must not route into the
// NODATA denial path just because NSEC/NSEC3 records are present. ---

func TestIsDenialForType(t *testing.T) {
	nsec := []dnspkg.NSECRecord{{Owner: "host.example.com.", NextDomain: "z.example.com."}}
	tests := []struct {
		name  string
		qr    *dnspkg.QueryResult
		qtype uint16
		want  bool
	}{
		{
			"positive A answer with NSEC wildcard proof in authority is not a denial",
			&dnspkg.QueryResult{RCode: miekgdns.RcodeSuccess, AnswerTypes: []uint16{miekgdns.TypeA, miekgdns.TypeRRSIG}, NSEC: nsec},
			miekgdns.TypeA, false,
		},
		{
			"empty answer with NSEC is NODATA",
			&dnspkg.QueryResult{RCode: miekgdns.RcodeSuccess, NSEC: nsec},
			miekgdns.TypeA, true,
		},
		{
			"NXDOMAIN is a denial",
			&dnspkg.QueryResult{RCode: miekgdns.RcodeNameError, NSEC: nsec},
			miekgdns.TypeA, true,
		},
		{
			"CNAME answer is not a denial",
			&dnspkg.QueryResult{RCode: miekgdns.RcodeSuccess, CNAME: []dnspkg.CNAMERecord{{Name: "host.example.com.", Target: "t.example.com."}}, AnswerTypes: []uint16{miekgdns.TypeCNAME}},
			miekgdns.TypeA, false,
		},
		{
			"answer holding only a different type is NODATA for the queried type",
			&dnspkg.QueryResult{RCode: miekgdns.RcodeSuccess, AnswerTypes: []uint16{miekgdns.TypeTXT}},
			miekgdns.TypeA, true,
		},
		{
			"SERVFAIL is not a denial",
			&dnspkg.QueryResult{RCode: miekgdns.RcodeServerFailure},
			miekgdns.TypeA, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDenialForType(tt.qr, tt.qtype); got != tt.want {
				t.Errorf("isDenialForType = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- Item B: descendants of an insecure zone must read insecure, while
// indeterminate/bogus parents stay fail-closed. ---

func TestNextParentDNSKEY(t *testing.T) {
	prev := []dnspkg.DNSKEYRecord{{KeyTag: 1}}
	zoneKeys := []dnspkg.DNSKEYRecord{{KeyTag: 2}}

	zr := func(status ValidationStatus, keys []dnspkg.DNSKEYRecord) *ZoneResult {
		r := NewZoneResult("child.example.com.")
		r.Status = status
		r.DNSKEY = keys
		return r
	}

	tests := []struct {
		name string
		zr   *ZoneResult
		want []dnspkg.DNSKEYRecord
	}{
		{"secure zone threads its own keys", zr(StatusSecure, zoneKeys), zoneKeys},
		{"insecure zone clears the keys", zr(StatusInsecure, nil), nil},
		{"insecure island of security clears the keys", zr(StatusInsecure, zoneKeys), nil},
		{"indeterminate zone without keys keeps the previous keys", zr(StatusIndeterminate, nil), prev},
		{"bogus zone without keys keeps the previous keys", zr(StatusBogus, nil), prev},
		{"indeterminate zone with fetched keys threads them", zr(StatusIndeterminate, zoneKeys), zoneKeys},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextParentDNSKEY(prev, tt.zr)
			if len(got) != len(tt.want) {
				t.Fatalf("nextParentDNSKEY returned %d keys, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i].KeyTag != tt.want[i].KeyTag {
					t.Fatalf("nextParentDNSKEY key %d = tag %d, want tag %d", i, got[i].KeyTag, tt.want[i].KeyTag)
				}
			}
		})
	}
}

// A zone cut below an insecure delegation: with the parent keys cleared the
// child reaches the insecure-ancestor branch and reads insecure; with the
// nearest signed ancestor's keys still threaded (the pre-fix behavior) the
// same child demands an impossible DS-absence proof and reads indeterminate.
func TestChildOfInsecureZoneReadsInsecure(t *testing.T) {
	v := &Validator{}
	signedAncestorKeys := []dnspkg.DNSKEYRecord{{KeyTag: 42}}

	insecureParent := NewZoneResult("example.com.")
	insecureParent.Status = StatusInsecure

	threaded := nextParentDNSKEY(signedAncestorKeys, insecureParent)
	if len(threaded) != 0 {
		t.Fatalf("an insecure zone must clear the threaded parent keys, got %d keys", len(threaded))
	}

	child := NewZoneResult("sub.example.com.")
	v.finalizeNoDSDelegation(child, "sub.example.com.", "example.com.", threaded, nil)
	if child.Status != StatusInsecure {
		t.Fatalf("child of an insecure zone must read insecure, got %s", child.Status)
	}

	// The secure-parent path stays fail-closed: without a DS-absence proof the
	// child of a SIGNED parent is still indeterminate, not insecure.
	pre := NewZoneResult("sub.example.com.")
	v.finalizeNoDSDelegation(pre, "sub.example.com.", "example.com.", signedAncestorKeys, nil)
	if pre.Status != StatusIndeterminate {
		t.Fatalf("child of a signed parent without a DS-absence proof must stay indeterminate, got %s", pre.Status)
	}
}

// --- Item C: RFC 4035 §5.3.3 — an RRset is authenticated if ANY covering
// RRSIG verifies under an authenticated key, so a double-signature rollover
// whose non-matching signature sorts first must not read bogus. ---

func TestFindRRSIGsForType(t *testing.T) {
	rrsigs := []dnspkg.RRSIGRecord{
		{TypeCovered: 48, KeyTag: 111},
		{TypeCovered: 43, KeyTag: 222},
		{TypeCovered: 48, KeyTag: 333},
	}
	got := FindRRSIGsForType(48, rrsigs)
	if len(got) != 2 || got[0].KeyTag != 111 || got[1].KeyTag != 333 {
		t.Fatalf("FindRRSIGsForType(48) = %+v, want key tags 111 and 333 in order", got)
	}
	if got := FindRRSIGsForType(1, rrsigs); len(got) != 0 {
		t.Fatalf("FindRRSIGsForType(1) should find nothing, got %+v", got)
	}
}

func TestVerifyDNSKEYRRSIGByKeys_DoubleSignature(t *testing.T) {
	const zone = "example.com."
	kskA, signerA, recA := genTestDNSKEY(t, zone, 257) // genuine KSK (DS at parent)
	kskB, signerB, recB := genTestDNSKEY(t, zone, 257) // outgoing/rogue KSK
	kskC, signerC, recC := genTestDNSKEY(t, zone, 257) // second non-matched KSK

	dnskeys := []dnspkg.DNSKEYRecord{recA, recB, recC}
	rrsetKeys := []*miekgdns.DNSKEY{kskA, kskB, kskC}

	dsA := dsForKey(t, zone, recA)
	authed := CollectDSMatchedKeys([]dnspkg.DSRecord{dsA}, dnskeys, zone)
	if len(authed) != 1 || authed[0].KeyTag != recA.KeyTag {
		t.Fatalf("CollectDSMatchedKeys should authenticate only KSK-A (tag %d), got %+v", recA.KeyTag, authed)
	}

	sigA := signDNSKEYRRset(t, zone, rrsetKeys, signerA, recA.KeyTag)
	sigB := signDNSKEYRRset(t, zone, rrsetKeys, signerB, recB.KeyTag)
	sigC := signDNSKEYRRset(t, zone, rrsetKeys, signerC, recC.KeyTag)

	// Double signature with the non-matching RRSIGs sorted first: the RRset
	// must be accepted via the DS-matched signature.
	if err := VerifyDNSKEYRRSIGByKeys(zone, dnskeys, []dnspkg.RRSIGRecord{sigB, sigC, sigA}, authed); err != nil {
		t.Fatalf("an RRset with any one RRSIG under a DS-matched key must verify (RFC 4035 §5.3.3), got: %v", err)
	}

	// Every RRSIG by a non-authenticated key: still fail closed (R-080), with
	// an aggregate error naming all attempts.
	err := VerifyDNSKEYRRSIGByKeys(zone, dnskeys, []dnspkg.RRSIGRecord{sigB, sigC}, authed)
	if err == nil {
		t.Fatal("a DNSKEY RRset with no RRSIG under a DS-matched key was accepted; R-080 not enforced")
	}
	if !strings.Contains(err.Error(), "none of 2") {
		t.Fatalf("expected an aggregate error over both RRSIGs, got: %v", err)
	}
}

// signDSRRSIGRecord signs the DS RRset with signer/keyTag and returns the
// miekg RRSIG (for response assembly) and the RRSIGRecord a real parse would
// have produced.
func signDSRRSIGRecord(t *testing.T, zone, parentZone string, ds *miekgdns.DS, signer crypto.Signer, keyTag uint16) (*miekgdns.RRSIG, dnspkg.RRSIGRecord) {
	t.Helper()
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
		KeyTag:      keyTag,
		SignerName:  parentZone,
	}
	if err := sig.Sign(signer, []miekgdns.RR{ds}); err != nil {
		t.Fatalf("sign DS RRset: %v", err)
	}
	rec := dnspkg.RRSIGRecord{
		TypeCovered: miekgdns.TypeDS,
		Algorithm:   sig.Algorithm,
		Labels:      sig.Labels,
		OriginalTTL: 3600,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      keyTag,
		SignerName:  parentZone,
		Signature:   sig.Signature,
		IsValid:     true,
	}
	return sig, rec
}

func TestVerifyDSRRSIGSet_DoubleSignature(t *testing.T) {
	const zone = "sub.example.com."
	const parentZone = "example.com."

	_, genuineSigner, genuineRec := genTestDNSKEY(t, parentZone, 256)
	_, rogueSigner, rogueRec := genTestDNSKEY(t, parentZone, 256)
	ds := dnpkgDS(t, zone)

	rogueSig, _ := signDSRRSIGRecord(t, zone, parentZone, ds, rogueSigner, rogueRec.KeyTag)
	genuineSig, _ := signDSRRSIGRecord(t, zone, parentZone, ds, genuineSigner, genuineRec.KeyTag)

	msg := new(miekgdns.Msg)
	msg.SetQuestion(zone, miekgdns.TypeDS)
	msg.Answer = []miekgdns.RR{ds, rogueSig, genuineSig}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack DS response: %v", err)
	}
	parentKeys := []dnspkg.DNSKEYRecord{genuineRec}

	// Non-matching RRSIG first (double-signature rollover shape): the DS RRset
	// must verify via the second signature, and the authenticated DS RRset is
	// exactly the signed record (RA6X-007).
	v1 := &DSValidation{ParentZone: parentZone}
	authed := verifyDSRRSIGSet(v1, zone, parentZone, parentKeys, raw)
	if !v1.RRSIGVerified {
		t.Fatalf("DS RRset with any one RRSIG under the parent's keys must verify, got error: %s", v1.Error)
	}
	if v1.ParentSigningKey != genuineRec.KeyTag {
		t.Fatalf("ParentSigningKey = %d, want %d", v1.ParentSigningKey, genuineRec.KeyTag)
	}
	if v1.Error != "" {
		t.Fatalf("verified DS RRset should carry no error, got: %s", v1.Error)
	}
	if len(authed) != 1 || authed[0].KeyTag != ds.KeyTag || !strings.EqualFold(authed[0].Digest, ds.Digest) {
		t.Fatalf("authenticated DS RRset = %+v, want exactly the signed DS (tag %d)", authed, ds.KeyTag)
	}

	// The parent holds neither signing key: nothing verifies, nothing is returned.
	_, _, strangerRec := genTestDNSKEY(t, parentZone, 256)
	v2 := &DSValidation{ParentZone: parentZone}
	if got := verifyDSRRSIGSet(v2, zone, parentZone, []dnspkg.DNSKEYRecord{strangerRec}, raw); got != nil {
		t.Fatalf("DS RRset with no verifiable RRSIG must return no authenticated DS, got %+v", got)
	}
	if v2.RRSIGVerified || v2.Error == "" {
		t.Fatalf("DS RRset with no verifiable RRSIG must not read verified and must carry an error, got verified=%v error=%q", v2.RRSIGVerified, v2.Error)
	}

	// No covering RRSIG at all.
	unsigned := new(miekgdns.Msg)
	unsigned.SetQuestion(zone, miekgdns.TypeDS)
	unsigned.Answer = []miekgdns.RR{ds}
	rawUnsigned, err := unsigned.Pack()
	if err != nil {
		t.Fatalf("pack unsigned DS response: %v", err)
	}
	v3 := &DSValidation{ParentZone: parentZone}
	if got := verifyDSRRSIGSet(v3, zone, parentZone, parentKeys, rawUnsigned); got != nil || v3.RRSIGVerified {
		t.Fatalf("unsigned DS RRset must not authenticate, got %+v verified=%v", got, v3.RRSIGVerified)
	}
	if !strings.Contains(v3.Error, "no RRSIG") {
		t.Fatalf("expected a 'no RRSIG' error, got: %s", v3.Error)
	}

	// A signature by the right key but naming another zone as signer must not
	// authenticate the DS RRset for this parent (RA6X-007 parent-signer binding).
	wrongSigner, _ := signDSRRSIGRecord(t, zone, "other.example.", ds, genuineSigner, genuineRec.KeyTag)
	ws := new(miekgdns.Msg)
	ws.SetQuestion(zone, miekgdns.TypeDS)
	ws.Answer = []miekgdns.RR{ds, wrongSigner}
	rawWS, err := ws.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	v4 := &DSValidation{ParentZone: parentZone}
	if got := verifyDSRRSIGSet(v4, zone, parentZone, parentKeys, rawWS); got != nil || v4.RRSIGVerified {
		t.Fatalf("DS RRSIG naming another zone as signer must not authenticate, got %+v verified=%v", got, v4.RRSIGVerified)
	}
}

// --- Item D: verifyDSAbsence must enforce the RFC 9276 NSEC3 iteration cap
// before hashing, and an over-cap NSEC3 must never prove an insecure
// delegation. ---

// buildNSEC3DSAbsenceResponse builds a parent DS QueryResult whose authority
// section holds an NSEC3 matching the child's hash (NS set, DS clear) signed
// by a fresh parent ZSK — a genuine NSEC3 insecure-delegation proof.
func buildNSEC3DSAbsenceResponse(t *testing.T, child, parentZone string, iterations uint16) (*dnspkg.QueryResult, dnspkg.DNSKEYRecord) {
	t.Helper()
	const ttl = 300
	const saltHex = "ABCD"
	salt := []byte{0xab, 0xcd}

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

	childHash := computeNSEC3Hash(child, salt, iterations)
	nextHash := computeNSEC3Hash("next."+parentZone, salt, iterations)
	owner := strings.ToLower(childHash) + "." + parentZone

	nsec3 := &miekgdns.NSEC3{
		Hdr:        miekgdns.RR_Header{Name: owner, Rrtype: miekgdns.TypeNSEC3, Class: miekgdns.ClassINET, Ttl: ttl},
		Hash:       NSEC3HashSHA1,
		Flags:      0,
		Iterations: iterations,
		SaltLength: uint8(len(salt)),
		Salt:       saltHex,
		HashLength: 20,
		NextDomain: nextHash,
		TypeBitMap: []uint16{miekgdns.TypeNS, miekgdns.TypeRRSIG},
	}
	inception := time.Now().Add(-time.Hour)
	expiration := time.Now().Add(24 * time.Hour)
	sig := &miekgdns.RRSIG{
		Hdr:         miekgdns.RR_Header{Name: owner, Rrtype: miekgdns.TypeRRSIG, Class: miekgdns.ClassINET, Ttl: ttl},
		TypeCovered: miekgdns.TypeNSEC3,
		Algorithm:   miekgdns.ECDSAP256SHA256,
		Labels:      uint8(miekgdns.CountLabel(owner)),
		OrigTtl:     ttl,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      dnskey.KeyTag(),
		SignerName:  parentZone,
	}
	if err := sig.Sign(signer, []miekgdns.RR{nsec3}); err != nil {
		t.Fatalf("sign NSEC3: %v", err)
	}

	msg := new(miekgdns.Msg)
	msg.SetQuestion(child, miekgdns.TypeDS)
	msg.Rcode = miekgdns.RcodeSuccess
	msg.Ns = []miekgdns.RR{nsec3, sig}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}

	qr := &dnspkg.QueryResult{
		RCode: miekgdns.RcodeSuccess,
		NSEC3: []dnspkg.NSEC3Record{{
			Owner:       owner,
			HashedOwner: childHash,
			Algorithm:   NSEC3HashSHA1,
			Flags:       0,
			Iterations:  iterations,
			Salt:        saltHex,
			NextHashed:  nextHash,
			TypeBitmap:  []string{"NS", "RRSIG"},
		}},
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

func TestVerifyDSAbsenceNSEC3IterationCap(t *testing.T) {
	v := &Validator{}
	const parentZone = "example.com."
	const child = "sub.example.com."
	_, _, parentKey := genTestDNSKEY(t, parentZone, 256)

	overCap := &dnspkg.QueryResult{
		RCode: miekgdns.RcodeSuccess,
		NSEC3: []dnspkg.NSEC3Record{{
			HashedOwner: "0123456789ABCDEFGHIJKLMNOPQRSTUV",
			Algorithm:   NSEC3HashSHA1,
			Iterations:  1000,
			Salt:        "ABCD",
			NextHashed:  "V0123456789ABCDEFGHIJKLMNOPQRSTU",
			TypeBitmap:  []string{"NS"},
		}},
	}
	proof, ok := v.verifyDSAbsence(child, parentZone, []dnspkg.DNSKEYRecord{parentKey}, overCap)
	if ok {
		t.Fatal("an NSEC3 with iterations over the RFC 9276 cap must not prove DS absence")
	}
	if proof == nil || !strings.Contains(proof.Error, "RFC 9276") {
		t.Fatalf("expected an RFC 9276 cap error, got %+v", proof)
	}

	// Through finalizeNoDSDelegation the over-cap NSEC3 yields the fail-closed
	// non-insecure outcome (bogus), never an insecure downgrade.
	r := NewZoneResult(child)
	v.finalizeNoDSDelegation(r, child, parentZone, []dnspkg.DNSKEYRecord{parentKey}, overCap)
	if r.Status != StatusBogus {
		t.Fatalf("over-cap NSEC3 DS-absence proof should yield bogus, got %s", r.Status)
	}

	// A modest iteration count is unaffected: a signed NSEC3 delegation match
	// still proves the insecure delegation.
	qr, signedParentKey := buildNSEC3DSAbsenceResponse(t, child, parentZone, 10)
	proof10, ok10 := v.verifyDSAbsence(child, parentZone, []dnspkg.DNSKEYRecord{signedParentKey}, qr)
	if !ok10 {
		t.Fatalf("a signed NSEC3 with iterations=10 must still prove DS absence, got error: %s", proof10.Error)
	}
	r10 := NewZoneResult(child)
	v.finalizeNoDSDelegation(r10, child, parentZone, []dnspkg.DNSKEYRecord{signedParentKey}, qr)
	if r10.Status != StatusInsecure {
		t.Fatalf("valid NSEC3 absence proof should yield insecure, got %s", r10.Status)
	}
}
