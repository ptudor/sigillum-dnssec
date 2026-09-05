package validator

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// RA6X-007 (Critical): an unsigned DS appended to the Additional (or Authority)
// section of a genuinely signed DS response must never enter chain matching.
// Before the fix the parser merged every section into one DS slice and chain
// construction consumed that slice, so an attacker's DS for their own key
// authenticated an attacker-controlled child DNSKEY RRset while the genuine
// parent signature over the real DS still passed. These tests drive the real
// validateZone path through the hermetic harness.

// ra6x007Fixture wires parent "test." and child "child.test." into the mock.
type ra6x007Fixture struct {
	m         *mockDNS
	parent    *testZone
	genuine   *testZone // the child zone the parent actually delegates to (key A)
	attacker  *testZone // attacker keys for the same child name (key B)
	hierarchy []string
}

func newRA6X007Fixture(t *testing.T) *ra6x007Fixture {
	t.Helper()
	m := newMockDNS(t)
	f := &ra6x007Fixture{
		m:         m,
		parent:    newTestZone(t, "test."),
		genuine:   newTestZone(t, "child.test."),
		attacker:  newTestZone(t, "child.test."),
		hierarchy: []string{".", "test.", "child.test."},
	}
	m.serveInfra("test.")
	m.serveInfra("child.test.")
	return f
}

// validateChild runs validateZone for the child with the parent's authenticated
// DNSKEY set threaded in, exactly as the chain walk would.
func (f *ra6x007Fixture) validateChild(t *testing.T) *ZoneResult {
	t.Helper()
	v := f.m.newValidator()
	zr, err := v.validateZone(testCtx(t), "child.test.", f.hierarchy, f.parent.keyRecords(), false)
	if err != nil {
		t.Fatalf("validateZone: %v", err)
	}
	return zr
}

// attackerDS returns an unsigned DS for the attacker's KSK at the given owner.
func (f *ra6x007Fixture) attackerDS(t *testing.T, owner string) *dns.DS {
	t.Helper()
	d := f.attacker.ds(t)
	d.Hdr.Name = dns.Fqdn(owner)
	return d
}

func TestRA6X007_InjectedDSCannotAuthenticateAttackerChild(t *testing.T) {
	cases := []struct {
		name      string
		authority []dns.RR
		extra     []dns.RR
	}{
		{name: "additional, same owner", extra: []dns.RR{}},
		{name: "additional, unrelated owner"},
		{name: "authority, same owner"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRA6X007Fixture(t)
			var authority, extra []dns.RR
			switch tc.name {
			case "additional, same owner":
				extra = []dns.RR{f.attackerDS(t, "child.test.")}
			case "additional, unrelated owner":
				extra = []dns.RR{f.attackerDS(t, "unrelated.invalid.")}
			case "authority, same owner":
				authority = []dns.RR{f.attackerDS(t, "child.test.")}
			}
			// Parent serves the genuine signed DS for key A plus the injected DS for B.
			f.parent.serveDS(t, f.m, f.genuine, authority, extra)
			// The child answers entirely with the attacker's keys, signed only by B.
			f.attacker.serveDNSKEY(t, f.m)

			zr := f.validateChild(t)
			if zr.Status != StatusBogus {
				t.Fatalf("attacker-controlled child authenticated via injected DS: status=%s errors=%v", zr.Status, zr.Errors)
			}
			// The injected DS must not appear as the delegation's DS RRset or
			// in the chain link; the served (Answer) DS remains visible.
			for _, d := range zr.DS {
				if d.KeyTag == f.attacker.ksk.KeyTag() {
					t.Fatalf("injected DS promoted into ZoneResult.DS: %+v", zr.DS)
				}
			}
			if zr.ChainLink != nil && zr.ChainLink.DSMatchesKSK {
				t.Fatalf("chain link must not be established: %+v", zr.ChainLink)
			}
		})
	}
}

func TestRA6X007_GenuineChainStillSecure(t *testing.T) {
	f := newRA6X007Fixture(t)
	// Legitimate Additional content (glue for the child's nameserver) must not
	// disturb authentication.
	glue := &dns.A{Hdr: rrHdr("ns.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.10")}
	f.parent.serveDS(t, f.m, f.genuine, nil, []dns.RR{glue})
	f.genuine.serveDNSKEY(t, f.m)

	zr := f.validateChild(t)
	if zr.Status != StatusSecure {
		t.Fatalf("genuine chain must be secure, got %s errors=%v", zr.Status, zr.Errors)
	}
	if zr.ChainLink == nil || !zr.ChainLink.DSMatchesKSK || zr.ChainLink.KeyTag != f.genuine.ksk.KeyTag() {
		t.Fatalf("chain link = %+v, want DS→KSK %d", zr.ChainLink, f.genuine.ksk.KeyTag())
	}
	if len(zr.ChainLink.ParentDS) != 1 || zr.ChainLink.ParentDS[0].KeyTag != f.genuine.ksk.KeyTag() {
		t.Fatalf("chain link ParentDS must be the exact authenticated DS RRset, got %+v", zr.ChainLink.ParentDS)
	}
	if len(zr.DS) != 1 || zr.DS[0].Section != dnspkg.SectionAnswer || dns.CanonicalName(zr.DS[0].Owner) != "child.test." {
		t.Fatalf("ZoneResult.DS = %+v, want the Answer-section DS owned by the child", zr.DS)
	}
	if zr.DSValidation == nil || !zr.DSValidation.RRSIGVerified || zr.DSValidation.ParentSigningKey != f.parent.zsk.KeyTag() {
		t.Fatalf("DS validation = %+v", zr.DSValidation)
	}
}

// The same boundary applies to the child's DNSKEY RRset: a DNSKEY parked in the
// Additional section is not part of the RRset. It must neither authenticate
// anything nor (as before, via the reconstructed merged slice) break the
// verification of the genuine RRset.
func TestRA6X007_AdditionalDNSKEYIsNotPartOfRRset(t *testing.T) {
	f := newRA6X007Fixture(t)
	f.parent.serveDS(t, f.m, f.genuine, nil, nil)
	rrset := f.genuine.dnskeyRRset()
	sig := f.genuine.signKSK(t, rrset...)
	f.m.respond("child.test.", dns.TypeDNSKEY, dns.RcodeSuccess, append(rrset, sig), nil, []dns.RR{f.attacker.ksk})

	zr := f.validateChild(t)
	if zr.Status != StatusSecure {
		t.Fatalf("genuine RRset with an Additional-section DNSKEY must verify, got %s errors=%v", zr.Status, zr.Errors)
	}
	if len(zr.DNSKEY) != 2 {
		t.Fatalf("ZoneResult.DNSKEY must be the Answer-section RRset only, got %d keys", len(zr.DNSKEY))
	}
	for _, k := range zr.DNSKEY {
		if k.KeyTag == f.attacker.ksk.KeyTag() && k.PublicKey == f.attacker.ksk.PublicKey {
			t.Fatalf("Additional-section DNSKEY promoted into the zone's key set")
		}
	}
	// And an attacker key in Additional that signs the RRset cannot authenticate it.
	f2 := newRA6X007Fixture(t)
	f2.parent.serveDS(t, f2.m, f2.genuine, nil, nil)
	mixed := append(f2.genuine.dnskeyRRset(), f2.attacker.ksk)
	sigB := f2.attacker.signKSK(t, mixed...)
	f2.m.respond("child.test.", dns.TypeDNSKEY, dns.RcodeSuccess, append(f2.genuine.dnskeyRRset(), sigB), nil, []dns.RR{f2.attacker.ksk})
	zr2 := f2.validateChild(t)
	if zr2.Status != StatusBogus {
		t.Fatalf("DNSKEY RRset signed only by a non-DS-matched key must be bogus, got %s", zr2.Status)
	}
}

// Denial records: only Answer/Authority records are evidence, and only those
// whose RRset signature verified may prove anything. An unsigned NSEC injected
// alongside a genuine signed one is ignored rather than either promoted or
// allowed to poison the whole proof.
func TestRA6X007_DenialEvidenceBoundary(t *testing.T) {
	const parentZone = "example.com."
	const child = "sub.example.com."
	parent := newTestZone(t, parentZone)
	genuine := &dns.NSEC{Hdr: rrHdr(child, dns.TypeNSEC), NextDomain: "zzz.example.com.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC}}
	sig := parent.signZSK(t, genuine)
	forged := &dns.NSEC{Hdr: rrHdr(child, dns.TypeNSEC), NextDomain: "zzz.example.com.", TypeBitMap: []uint16{dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC}}

	build := func(authority, extra []dns.RR) *dnspkg.QueryResult {
		msg := new(dns.Msg)
		msg.SetQuestion(child, dns.TypeDS)
		msg.Ns = authority
		msg.Extra = extra
		raw, err := msg.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		qr := &dnspkg.QueryResult{RCode: dns.RcodeSuccess, RawResponse: raw}
		dnspkg.NewQuerier(0)
		for _, rr := range authority {
			if n, ok := rr.(*dns.NSEC); ok {
				qr.NSEC = append(qr.NSEC, dnspkg.NSECFromRR(n, dnspkg.SectionAuthority))
			}
		}
		for _, rr := range extra {
			if n, ok := rr.(*dns.NSEC); ok {
				qr.NSEC = append(qr.NSEC, dnspkg.NSECFromRR(n, dnspkg.SectionAdditional))
			}
		}
		return qr
	}
	v := &Validator{}
	keys := parent.keyRecords()

	// Genuine signed NSEC in Authority proves DS absence.
	if proof, ok := v.verifyDSAbsence(child, parentZone, keys, build([]dns.RR{genuine, sig}, nil)); !ok {
		t.Fatalf("genuine authority NSEC must prove DS absence: %+v", proof)
	}
	// An unsigned forged NSEC (DS bit set) in Additional is not evidence: the
	// genuine proof still stands and the forged record is not consulted.
	if proof, ok := v.verifyDSAbsence(child, parentZone, keys, build([]dns.RR{genuine, sig}, []dns.RR{forged})); !ok {
		t.Fatalf("Additional-section NSEC must not poison the proof: %+v", proof)
	}
	// Only an Additional-section NSEC, unsigned: there is no denial evidence
	// at all — never a verified proof.
	if proof, ok := v.verifyDSAbsence(child, parentZone, keys, build(nil, []dns.RR{genuine, sig})); ok || !strings.Contains(proof.Error, "no NSEC/NSEC3") {
		t.Fatalf("Additional-only NSEC must not be denial evidence: ok=%v %+v", ok, proof)
	}
	// A forged record in Authority beside the genuine one is excluded (not
	// verifiable) and the genuine record still proves absence.
	if proof, ok := v.verifyDSAbsence(child, parentZone, keys, build([]dns.RR{forged, genuine, sig}, nil)); ok {
		// Both records share the owner and therefore one RRset; the signature
		// covers only the genuine record, so the served RRset does not verify.
		t.Fatalf("an RRset altered by an injected record must not verify: %+v", proof)
	}
	unrelatedForged := &dns.NSEC{Hdr: rrHdr("other.example.com.", dns.TypeNSEC), NextDomain: "zzz.example.com.", TypeBitMap: []uint16{dns.TypeA}}
	if proof, ok := v.verifyDSAbsence(child, parentZone, keys, build([]dns.RR{unrelatedForged, genuine, sig}, nil)); !ok {
		t.Fatalf("an unverifiable unrelated NSEC RRset must be ignored, not fail the genuine proof: %+v", proof)
	}
}

// Leaf data: an RRSIG that is not in the Answer section at the queried owner
// is not a candidate for the leaf RRset, so a response whose only signature
// sits in Additional is unsigned data (bogus), driven through the real
// verifyActualRecord path.
func TestRA6X007_LeafSignatureMustBeInAnswer(t *testing.T) {
	m := newMockDNS(t)
	zone := newTestZone(t, "child.test.")
	m.serveInfra("child.test.")
	a := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	sig := zone.signZSK(t, a)

	// Signature only in Additional: bogus.
	m.respond("www.child.test.", dns.TypeA, dns.RcodeSuccess, []dns.RR{a}, nil, []dns.RR{sig})
	v := m.newValidator()
	rv := v.verifyActualRecord(testCtx(t), "www.child.test.", "child.test.", zone.keyRecords())
	if rv == nil || rv.RRSIGVerified {
		t.Fatalf("leaf signed only in Additional must not verify: %+v", rv)
	}
	if verdict, _ := recordValidationVerdict(rv); verdict != StatusBogus {
		t.Fatalf("verdict = %s, want bogus", verdict)
	}

	// Signature in Answer: secure.
	m.respond("www.child.test.", dns.TypeA, dns.RcodeSuccess, []dns.RR{a, sig}, nil, nil)
	rv = v.verifyActualRecord(testCtx(t), "www.child.test.", "child.test.", zone.keyRecords())
	if rv == nil || !rv.RRSIGVerified || rv.SigningKeyTag != zone.zsk.KeyTag() {
		t.Fatalf("genuine leaf must verify: %+v", rv)
	}
}
