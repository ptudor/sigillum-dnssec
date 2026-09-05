package validator

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// RA6X-016 (High): trusted key material must keep its zone identity. Two zones
// that reuse the same key must not be able to authenticate each other's
// signatures: DNSKEY, DS, denial and leaf evidence replayed from zone A into
// zone B is rejected, while each zone's own evidence (and the legitimate
// shared-key deployment) still verifies.

// sharedKeyZones returns two zones, a.test. and b.test., that share the same
// KSK and ZSK private material (the DNSKEY records differ only in owner).
func sharedKeyZones(t *testing.T) (*testZone, *testZone) {
	t.Helper()
	a := newTestZone(t, "a.test.")
	b := &testZone{name: "b.test."}
	b.ksk = dns.Copy(a.ksk).(*dns.DNSKEY)
	b.ksk.Hdr.Name = "b.test."
	b.zsk = dns.Copy(a.zsk).(*dns.DNSKEY)
	b.zsk.Hdr.Name = "b.test."
	b.kskSigner, b.zskSigner = a.kskSigner, a.zskSigner
	return a, b
}

func packMsg(t *testing.T, qname string, qtype uint16, rcode int, answer, authority []dns.RR) []byte {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(qname, qtype)
	msg.Rcode = rcode
	msg.Answer = answer
	msg.Ns = authority
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return raw
}

func dsRecordsOf(t *testing.T, z *testZone) []dnspkg.DSRecord {
	t.Helper()
	return []dnspkg.DSRecord{dnspkg.DSFromRR(z.ds(t), dnspkg.SectionAnswer)}
}

// The review's probe, at the DNSKEY boundary: a signature produced at zone A
// must not authenticate the same key material as zone B's DNSKEY RRset, even
// though B's DS (computed for B) matches that key material.
func TestRA6X016_DNSKEYEvidenceIsZoneBound(t *testing.T) {
	a, b := sharedKeyZones(t)
	keysA, keysB := a.keyRecords(), b.keyRecords()

	// Each zone's DS authenticates only keys owned by that zone.
	authedA := CollectDSMatchedKeys(dsRecordsOf(t, a), keysA, a.name)
	authedB := CollectDSMatchedKeys(dsRecordsOf(t, b), keysB, b.name)
	if len(authedA) != 1 || len(authedB) != 1 {
		t.Fatalf("each zone's own DS must match its own KSK: a=%d b=%d", len(authedA), len(authedB))
	}
	if cross := CollectDSMatchedKeys(dsRecordsOf(t, b), keysA, b.name); len(cross) != 0 {
		t.Fatalf("zone A's DNSKEY records must not be matched as zone B's keys, got %+v", cross)
	}

	rawA := packMsg(t, a.name, dns.TypeDNSKEY, dns.RcodeSuccess, append(a.dnskeyRRset(), a.signKSK(t, a.dnskeyRRset()...)), nil)
	rawB := packMsg(t, b.name, dns.TypeDNSKEY, dns.RcodeSuccess, append(b.dnskeyRRset(), b.signKSK(t, b.dnskeyRRset()...)), nil)

	// Originals verify.
	if _, err := VerifyDNSKEYRRsetFromResponse(rawA, a.name, authedA); err != nil {
		t.Fatalf("zone A's own DNSKEY RRset must verify: %v", err)
	}
	if _, err := VerifyDNSKEYRRsetFromResponse(rawB, b.name, authedB); err != nil {
		t.Fatalf("zone B's own DNSKEY RRset (legitimately shared key) must verify: %v", err)
	}
	// Replays do not.
	if _, err := VerifyDNSKEYRRsetFromResponse(rawA, b.name, authedB); err == nil {
		t.Fatal("zone A's DNSKEY response replayed as zone B's was accepted")
	}
	if _, err := VerifyDNSKEYRRsetFromResponse(rawB, a.name, authedA); err == nil {
		t.Fatal("zone B's DNSKEY response replayed as zone A's was accepted")
	}

	// B's own RRset but signed "at A" (signer name a.test., same key): rejected.
	sigAtA := signWith(t, a.name, a.ksk, a.kskSigner, b.dnskeyRRset())
	rawBSignedAtA := packMsg(t, b.name, dns.TypeDNSKEY, dns.RcodeSuccess, append(b.dnskeyRRset(), sigAtA), nil)
	if _, err := VerifyDNSKEYRRsetFromResponse(rawBSignedAtA, b.name, authedB); err == nil {
		t.Fatal("zone B's DNSKEY RRset with a signature naming zone A as signer was accepted")
	}

	// Record-level helper (the review's exact call shape): keys authenticated
	// for child zone B, signature made at zone A → rejected; B's own → accepted.
	sigA := a.signKSK(t, a.dnskeyRRset()...)
	sigRecAtA := dnspkg.RRSIGFromRR(sigA, dnspkg.SectionAnswer, time.Now())
	if err := VerifyDNSKEYRRSIGByKeys(b.name, keysB, []dnspkg.RRSIGRecord{sigRecAtA}, authedB); err == nil {
		t.Fatal("record-level DNSKEY verification accepted a signature made at another zone")
	}
	sigB := b.signKSK(t, b.dnskeyRRset()...)
	sigRecB := dnspkg.RRSIGFromRR(sigB, dnspkg.SectionAnswer, time.Now())
	if err := VerifyDNSKEYRRSIGByKeys(b.name, keysB, []dnspkg.RRSIGRecord{sigRecB}, authedB); err != nil {
		t.Fatalf("record-level DNSKEY verification must accept the zone's own signature: %v", err)
	}
	// A DNSKEY record parsed at another owner is not part of B's RRset and is
	// never rewritten to make the signature fit.
	if err := VerifyDNSKEYRRSIGByKeys(b.name, append(keysB, keysA[0]), []dnspkg.RRSIGRecord{sigRecB}, authedB); err == nil {
		t.Fatal("a DNSKEY owned by another zone was folded into B's RRset")
	}
}

// DS evidence is bound to the actual parent: a DS RRset signed by parent P1
// does not authenticate under sibling parent P2's identical key material.
func TestRA6X016_DSEvidenceIsParentBound(t *testing.T) {
	p1, p2 := sharedKeyZones(t) // a.test. and b.test. act as two parents
	child := newTestZone(t, "c.a.test.")
	ds := child.ds(t)
	sig := p1.signZSK(t, ds)
	raw := packMsg(t, child.name, dns.TypeDS, dns.RcodeSuccess, []dns.RR{ds, sig}, nil)

	v1 := &DSValidation{ParentZone: p1.name}
	if got := verifyDSRRSIGSet(v1, child.name, p1.name, p1.keyRecords(), raw); len(got) != 1 || !v1.RRSIGVerified {
		t.Fatalf("DS signed by the actual parent must verify: %+v err=%s", got, v1.Error)
	}
	v2 := &DSValidation{ParentZone: p2.name}
	if got := verifyDSRRSIGSet(v2, child.name, p2.name, p2.keyRecords(), raw); got != nil || v2.RRSIGVerified {
		t.Fatalf("DS signed by another parent must not verify under the sibling's shared key: %+v", got)
	}
}

// Denial evidence is bound to the zone whose keys are used: an NSEC owned in
// and signed by zone A never denies anything for zone B.
func TestRA6X016_DenialEvidenceIsZoneBound(t *testing.T) {
	a, b := sharedKeyZones(t)
	nsecA := &dns.NSEC{Hdr: rrHdr("x.a.test.", dns.TypeNSEC), NextDomain: "z.a.test.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}}
	rawA := packMsg(t, "y.a.test.", dns.TypeA, dns.RcodeNameError, nil, []dns.RR{nsecA, a.signZSK(t, nsecA)})

	if _, _, err := VerifyDenialRRsetsFromResponse(rawA, dns.TypeNSEC, a.keyRecords(), a.name); err != nil {
		t.Fatalf("zone A's own denial must verify: %v", err)
	}
	if _, _, err := VerifyDenialRRsetsFromResponse(rawA, dns.TypeNSEC, b.keyRecords(), b.name); err == nil {
		t.Fatal("zone A's NSEC was accepted as zone B's denial evidence")
	}
	// An NSEC owned inside B but signed "at A" with the shared key: rejected.
	// An apex NSEC b.test. → z.b.test. covers both y.b.test. and *.b.test., so it
	// is a complete NXDOMAIN proof on its own (RFC 4035 §5.4).
	nsecB := &dns.NSEC{Hdr: rrHdr("b.test.", dns.TypeNSEC), NextDomain: "z.b.test.", TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY}}
	rawBAtA := packMsg(t, "y.b.test.", dns.TypeA, dns.RcodeNameError, nil, []dns.RR{nsecB, signWith(t, a.name, a.zsk, a.zskSigner, []dns.RR{nsecB})})
	if _, _, err := VerifyDenialRRsetsFromResponse(rawBAtA, dns.TypeNSEC, b.keyRecords(), b.name); err == nil {
		t.Fatal("an NSEC in zone B signed with zone A as signer was accepted")
	}
	// The same NSEC properly signed by B verifies, and the full NSEC denial
	// wrapper rejects the replay while accepting the original.
	sigB := b.signZSK(t, nsecB)
	rawB := packMsg(t, "y.b.test.", dns.TypeA, dns.RcodeNameError, nil, []dns.RR{nsecB, sigB})
	if _, _, err := VerifyDenialRRsetsFromResponse(rawB, dns.TypeNSEC, b.keyRecords(), b.name); err != nil {
		t.Fatalf("zone B's own denial must verify: %v", err)
	}
	recB := dnspkg.NSECFromRR(nsecB, dnspkg.SectionAuthority)
	sigRecB := []dnspkg.RRSIGRecord{dnspkg.RRSIGFromRR(sigB, dnspkg.SectionAuthority, time.Now())}
	if proof := VerifyNSECDenialWithRRSIG("y.b.test.", dns.TypeA, []dnspkg.NSECRecord{recB}, sigRecB, b.keyRecords(), b.name, rawB, dns.RcodeNameError); !proof.Verified {
		t.Fatalf("zone B's own NXDOMAIN proof must verify: %s", proof.Error)
	}
	if proof := VerifyNSECDenialWithRRSIG("y.b.test.", dns.TypeA, []dnspkg.NSECRecord{recB}, sigRecB, b.keyRecords(), b.name, rawBAtA, dns.RcodeNameError); proof.Verified {
		t.Fatal("NXDOMAIN proof signed at another zone was accepted")
	}
}

// Leaf evidence: a signature over B's record that names A as signer (same key
// material) is not B's evidence.
func TestRA6X016_LeafEvidenceIsZoneBound(t *testing.T) {
	a, b := sharedKeyZones(t)
	rr := &dns.A{Hdr: rrHdr("www.b.test.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	rawAtA := packMsg(t, "www.b.test.", dns.TypeA, dns.RcodeSuccess, []dns.RR{rr, signWith(t, a.name, a.zsk, a.zskSigner, []dns.RR{rr})}, nil)
	rawAtB := packMsg(t, "www.b.test.", dns.TypeA, dns.RcodeSuccess, []dns.RR{rr, b.signZSK(t, rr)}, nil)

	if _, err := VerifyRRsetFromResponse(rawAtB, dns.TypeA, b.keyRecords(), "www.b.test.", b.name, true); err != nil {
		t.Fatalf("zone B's own leaf signature must verify: %v", err)
	}
	if _, err := VerifyRRsetFromResponse(rawAtA, dns.TypeA, b.keyRecords(), "www.b.test.", b.name, true); err == nil {
		t.Fatal("leaf signature naming another zone as signer was accepted under B's keys")
	}
	// Even without an expected-signer argument, a key that carries its owner
	// refuses to verify a signature naming another zone.
	if _, err := VerifyRRsetFromResponse(rawAtA, dns.TypeA, b.keyRecords(), "www.b.test.", "", true); err == nil {
		t.Fatal("owner-bearing key verified a signature naming another zone")
	}
}

// Caller level: through validateZone, zone B served with zone A's DNSKEY
// response (replay) or with its own RRset signed at A is bogus; B's own
// shared-key deployment is secure.
func TestRA6X016_ValidateZoneRejectsCrossZoneReplay(t *testing.T) {
	a, b := sharedKeyZones(t)
	parent := newTestZone(t, "test.")
	hierarchy := []string{".", "test.", "b.test."}

	run := func(t *testing.T, serve func(m *mockDNS)) *ZoneResult {
		t.Helper()
		m := newMockDNS(t)
		m.serveInfra("test.")
		m.serveInfra("b.test.")
		parent.serveDS(t, m, b, nil, nil)
		serve(m)
		v := m.newValidator()
		zr, err := v.validateZone(testCtx(t), "b.test.", hierarchy, parent.keyRecords(), false)
		if err != nil {
			t.Fatalf("validateZone: %v", err)
		}
		return zr
	}

	zr := run(t, func(m *mockDNS) { b.serveDNSKEY(t, m) })
	if zr.Status != StatusSecure {
		t.Fatalf("zone B's own shared-key deployment must be secure, got %s errors=%v", zr.Status, zr.Errors)
	}
	zr = run(t, func(m *mockDNS) {
		// The server answers B's DNSKEY query with A's DNSKEY RRset and signature.
		m.answer("b.test.", dns.TypeDNSKEY, append(a.dnskeyRRset(), a.signKSK(t, a.dnskeyRRset()...))...)
	})
	if zr.Status != StatusBogus {
		t.Fatalf("zone A's DNSKEY response replayed for zone B must be bogus, got %s errors=%v", zr.Status, zr.Errors)
	}
	zr = run(t, func(m *mockDNS) {
		rrset := b.dnskeyRRset()
		m.answer("b.test.", dns.TypeDNSKEY, append(rrset, signWith(t, a.name, a.ksk, a.kskSigner, rrset))...)
	})
	if zr.Status != StatusBogus {
		t.Fatalf("zone B's DNSKEY RRset signed at zone A must be bogus, got %s errors=%v", zr.Status, zr.Errors)
	}
}
