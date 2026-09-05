package validator

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// Shared fixtures for the NSEC/NSEC3 semantics findings RA6X-010..013. Every
// end-to-end case drives the real verifyActualRecord / validateZone path with
// genuinely signed records served by the hermetic harness.

// leafFixture is a signed zone served by the mock, ready for leaf queries.
type leafFixture struct {
	m    *mockDNS
	zone *testZone
	v    *Validator
}

func newLeafFixture(t *testing.T, zoneName string) *leafFixture {
	t.Helper()
	m := newMockDNS(t)
	z := newTestZone(t, zoneName)
	m.serveInfra(zoneName)
	return &leafFixture{m: m, zone: z, v: m.newValidator()}
}

// nsecRR builds an NSEC record.
func nsecRR(owner, next string, types ...uint16) *dns.NSEC {
	return &dns.NSEC{Hdr: rrHdr(owner, dns.TypeNSEC), NextDomain: dns.Fqdn(next), TypeBitMap: types}
}

// nsec3Params describes one NSEC3 chain's parameters.
type nsec3Params struct {
	salt string
	iter uint16
}

func (p nsec3Params) saltBytes(t *testing.T) []byte {
	t.Helper()
	b, err := hexDecode(p.salt)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	return b
}

// hashOf returns the chain hash of name.
func (p nsec3Params) hashOf(t *testing.T, name string) string {
	return computeNSEC3Hash(name, p.saltBytes(t), p.iter)
}

// nsec3RR builds an NSEC3 record owned by H(ownerName) whose next hash is
// H(nextName) (or a literal hash when nextName starts with '='), in zone.
func (p nsec3Params) nsec3RR(t *testing.T, zone, ownerName, nextName string, flags uint8, types ...uint16) *dns.NSEC3 {
	t.Helper()
	ownerHash := p.hashOf(t, ownerName)
	nextHash := ""
	if strings.HasPrefix(nextName, "=") {
		nextHash = strings.TrimPrefix(nextName, "=")
	} else {
		nextHash = p.hashOf(t, nextName)
	}
	salt := p.salt
	if salt == "" {
		salt = "-"
	}
	return &dns.NSEC3{
		Hdr:        rrHdr(strings.ToLower(ownerHash)+"."+dns.Fqdn(zone), dns.TypeNSEC3),
		Hash:       NSEC3HashSHA1,
		Flags:      flags,
		Iterations: p.iter,
		SaltLength: uint8(len(p.saltBytes(t))),
		Salt:       salt,
		HashLength: 20,
		NextDomain: nextHash,
		TypeBitMap: types,
	}
}

// nsec3RRHashed builds an NSEC3 record from literal owner/next hashes.
func (p nsec3Params) nsec3RRHashed(t *testing.T, zone, ownerHash, nextHash string, flags uint8, types ...uint16) *dns.NSEC3 {
	t.Helper()
	salt := p.salt
	if salt == "" {
		salt = "-"
	}
	return &dns.NSEC3{
		Hdr:        rrHdr(strings.ToLower(ownerHash)+"."+dns.Fqdn(zone), dns.TypeNSEC3),
		Hash:       NSEC3HashSHA1,
		Flags:      flags,
		Iterations: p.iter,
		SaltLength: uint8(len(p.saltBytes(t))),
		Salt:       salt,
		HashLength: 20,
		NextDomain: nextHash,
		TypeBitMap: types,
	}
}

// bumpHash returns the base32hex hash immediately after h in lexicographic
// order (the last non-'V' character incremented, following ones reset to '0').
func bumpHash(h string) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
	b := []byte(strings.ToUpper(h))
	for i := len(b) - 1; i >= 0; i-- {
		idx := strings.IndexByte(alphabet, b[i])
		if idx < 0 || idx == len(alphabet)-1 {
			b[i] = '0'
			continue
		}
		b[i] = alphabet[idx+1]
		return string(b)
	}
	return string(b)
}

// signedAuthority signs every RRset in rrs with the zone's ZSK and returns
// the records interleaved with their signatures.
func (z *testZone) signedAuthority(t *testing.T, rrs ...dns.RR) []dns.RR {
	t.Helper()
	out := make([]dns.RR, 0, 2*len(rrs))
	for _, rr := range rrs {
		out = append(out, rr, z.signZSK(t, rr))
	}
	return out
}

// queryLeaf serves a response for qname/qtype and validates it.
func (f *leafFixture) queryLeaf(t *testing.T, qname string, qtype uint16, rcode int, answer, authority []dns.RR) *RecordValidation {
	t.Helper()
	f.v.SetQueryType(qtype)
	f.m.respond(qname, qtype, rcode, answer, authority, nil)
	return f.v.verifyActualRecord(testCtx(t), qname, f.zone.name, f.zone.keyRecords())
}

// ---------------------------------------------------------------------------
// RA6X-010 — NSEC NXDOMAIN must not accept existing empty non-terminals or
// cross delegation cuts.
// ---------------------------------------------------------------------------

func TestRA6X010_NSECNXDOMAINSemantics(t *testing.T) {
	const zone = "example.com."
	apexTypes := []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY}

	t.Run("endpoint below qname proves an empty non-terminal", func(t *testing.T) {
		f := newLeafFixture(t, zone)
		// The review's first example: NSEC example.com. → x.a.example.com. proves
		// a.example.com. exists (as an ENT), so NXDOMAIN for it is false.
		nsec := nsecRR(zone, "x.a.example.com.", apexTypes...)
		rv := f.queryLeaf(t, "a.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, nsec))
		if rv.DenialProof == nil || rv.DenialProof.Verified {
			t.Fatalf("NXDOMAIN for an existing empty non-terminal must not verify: %+v", rv)
		}
		if !strings.Contains(rv.Error, "empty non-terminal") {
			t.Fatalf("expected the ENT reason, got %q", rv.Error)
		}
		if verdict, _ := recordValidationVerdict(rv); verdict == StatusSecure {
			t.Fatal("verdict must not be secure")
		}
		// Semantic helper level too.
		rec := dnspkg.NSECFromRR(nsec, dnspkg.SectionAuthority)
		if _, err := VerifyNSECDenial("a.example.com.", dns.TypeA, []dnspkg.NSECRecord{rec}, dns.RcodeNameError); err == nil {
			t.Fatal("VerifyNSECDenial accepted an NXDOMAIN for an empty non-terminal")
		}
	})

	t.Run("parent NSEC cannot deny names inside a signed child delegation", func(t *testing.T) {
		f := newLeafFixture(t, zone)
		// The review's second example: NSEC child.example.com. → example.com. with
		// NS and DS is the parent side of a signed delegation; x.child... is in
		// the child zone.
		deleg := nsecRR("child.example.com.", zone, dns.TypeNS, dns.TypeDS, dns.TypeRRSIG, dns.TypeNSEC)
		rv := f.queryLeaf(t, "x.child.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, deleg))
		if rv.DenialProof == nil || rv.DenialProof.Verified {
			t.Fatalf("parent NSEC at a delegation must not deny names below it: %+v", rv)
		}
		if !strings.Contains(rv.Error, "delegation point") {
			t.Fatalf("expected the delegation reason, got %q", rv.Error)
		}
		// Same for NODATA below the cut.
		rv = f.queryLeaf(t, "x.child.example.com.", dns.TypeA, dns.RcodeSuccess, nil, f.zone.signedAuthority(t, deleg))
		if rv.DenialProof == nil || rv.DenialProof.Verified {
			t.Fatalf("parent NSEC at a delegation must not prove NODATA below it: %+v", rv)
		}
		// And below a DNAME.
		dname := nsecRR("redir.example.com.", "zz.example.com.", dns.TypeDNAME, dns.TypeRRSIG, dns.TypeNSEC)
		rv = f.queryLeaf(t, "x.redir.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, dname, nsecRR(zone, "redir.example.com.", apexTypes...)))
		if rv.DenialProof == nil || rv.DenialProof.Verified || !strings.Contains(rv.Error, "DNAME") {
			t.Fatalf("NSEC below a DNAME must not deny: %+v", rv)
		}
	})

	t.Run("a name outside the zone cannot be denied by it", func(t *testing.T) {
		f := newLeafFixture(t, zone)
		nsec := nsecRR(zone, "zzz.example.com.", apexTypes...)
		rv := f.queryLeaf(t, "other.example.net.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, nsec))
		if rv.DenialProof == nil || rv.DenialProof.Verified || !strings.Contains(rv.Error, "not within zone") {
			t.Fatalf("denial of a name outside the zone must be rejected: %+v", rv)
		}
	})

	t.Run("genuine child NXDOMAIN and apex wraparound are secure", func(t *testing.T) {
		f := newLeafFixture(t, "child.example.com.")
		// Ordinary NXDOMAIN inside the child zone, signed by the child.
		apex := nsecRR("child.example.com.", "m.child.example.com.", apexTypes...)
		rv := f.queryLeaf(t, "b.child.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, apex))
		if rv.DenialProof == nil || !rv.DenialProof.Verified {
			t.Fatalf("genuine child NXDOMAIN must verify: %+v", rv)
		}
		if verdict, _ := recordValidationVerdict(rv); verdict != StatusSecure {
			t.Fatalf("verdict = %s, want secure", verdict)
		}
		// Wraparound: the last NSEC points back to the apex and covers names
		// sorting after its owner; the apex NSEC covers the wildcard.
		last := nsecRR("m.child.example.com.", "child.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)
		rv = f.queryLeaf(t, "zzz.child.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, apex, last))
		if rv.DenialProof == nil || !rv.DenialProof.Verified {
			t.Fatalf("apex wraparound NXDOMAIN must verify: %+v", rv)
		}
	})

	t.Run("DS NODATA at an unsigned delegation stays insecure", func(t *testing.T) {
		m := newMockDNS(t)
		parent := newTestZone(t, "test.")
		child := newTestZone(t, "child.test.")
		m.serveInfra("test.")
		m.serveInfra("child.test.")
		deleg := nsecRR("child.test.", "zz.test.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)
		m.respond("child.test.", dns.TypeDS, dns.RcodeSuccess, nil, parent.signedAuthority(t, deleg), nil)
		child.serveDNSKEY(t, m)
		v := m.newValidator()
		zr, err := v.validateZone(testCtx(t), "child.test.", []string{".", "test.", "child.test."}, parent.keyRecords(), false)
		if err != nil {
			t.Fatalf("validateZone: %v", err)
		}
		if zr.Status != StatusInsecure || zr.DenialProof == nil || !zr.DenialProof.Verified {
			t.Fatalf("unsigned delegation with an authenticated DS-absence NSEC must be insecure: %s %+v", zr.Status, zr.DenialProof)
		}
	})
}

// ---------------------------------------------------------------------------
// RA6X-011 — NSEC wildcard proofs must establish the claimed closest encloser.
// ---------------------------------------------------------------------------

func TestRA6X011_NSECWildcardClosestEncloserAgreement(t *testing.T) {
	const zone = "example.com."
	f := newLeafFixture(t, zone)

	// expansion serves a wildcard-signed A for qname (Labels = wildcard depth).
	expansion := func(t *testing.T, wildcard, qname string) []dns.RR {
		t.Helper()
		w := &dns.A{Hdr: rrHdr(wildcard, dns.TypeA), A: net.ParseIP("192.0.2.9")}
		sig := f.zone.signZSK(t, w)
		sig.Hdr.Name = dns.Fqdn(qname)
		return []dns.RR{&dns.A{Hdr: rrHdr(qname, dns.TypeA), A: net.ParseIP("192.0.2.9")}, sig}
	}
	// The review's record: proves bar.example.com. exists and covers foo.bar.
	barNSEC := nsecRR("bar.example.com.", "z.bar.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)

	// *.example.com. cannot synthesize foo.bar.example.com. when bar exists.
	rv := f.queryLeaf(t, "foo.bar.example.com.", dns.TypeA, dns.RcodeSuccess, expansion(t, "*.example.com.", "foo.bar.example.com."), f.zone.signedAuthority(t, barNSEC))
	if !rv.Wildcard || rv.WildcardProofVerified {
		t.Fatalf("wildcard from *.example.com. must be rejected when a closer ancestor exists: %+v", rv)
	}
	if !strings.Contains(rv.Error, "closest encloser") {
		t.Fatalf("expected a closest-encloser disagreement, got %q", rv.Error)
	}
	if verdict, _ := recordValidationVerdict(rv); verdict != StatusBogus {
		t.Fatalf("verdict = %s, want bogus", verdict)
	}

	// *.bar.example.com. with the same NSEC is consistent and accepted.
	rv = f.queryLeaf(t, "foo.bar.example.com.", dns.TypeA, dns.RcodeSuccess, expansion(t, "*.bar.example.com.", "foo.bar.example.com."), f.zone.signedAuthority(t, barNSEC))
	if !rv.Wildcard || !rv.WildcardProofVerified || rv.WildcardProof.ClosestEncloser != "bar.example.com." {
		t.Fatalf("wildcard from *.bar.example.com. must be accepted: %+v err=%s", rv.WildcardProof, rv.Error)
	}
	if verdict, _ := recordValidationVerdict(rv); verdict != StatusSecure {
		t.Fatalf("verdict = %s, want secure", verdict)
	}

	// A query that is itself an existing empty non-terminal cannot be a
	// wildcard expansion: the NSEC's next name lies below it.
	entNSEC := nsecRR("a.example.com.", "x.bar.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)
	rv = f.queryLeaf(t, "bar.example.com.", dns.TypeA, dns.RcodeSuccess, expansion(t, "*.example.com.", "bar.example.com."), f.zone.signedAuthority(t, entNSEC))
	if !rv.Wildcard || rv.WildcardProofVerified || !strings.Contains(rv.Error, "empty non-terminal") {
		t.Fatalf("wildcard expansion of an existing empty non-terminal must be rejected: %+v", rv)
	}

	// Crossing a delegation: an ancestor NSEC with NS/no SOA blocks the proof.
	deleg := nsecRR("bar.example.com.", "z.bar.example.com.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)
	rv = f.queryLeaf(t, "foo.bar.example.com.", dns.TypeA, dns.RcodeSuccess, expansion(t, "*.bar.example.com.", "foo.bar.example.com."), f.zone.signedAuthority(t, deleg))
	if rv.WildcardProofVerified || !strings.Contains(rv.Error, "delegation point") {
		t.Fatalf("wildcard proof crossing a delegation must be rejected: %+v", rv)
	}

	// Canonical wraparound still works: last NSEC → apex covers a late name.
	last := nsecRR("m.example.com.", zone, dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)
	rv = f.queryLeaf(t, "zzz.example.com.", dns.TypeA, dns.RcodeSuccess, expansion(t, "*.example.com.", "zzz.example.com."), f.zone.signedAuthority(t, last))
	if !rv.WildcardProofVerified {
		t.Fatalf("wraparound NSEC must prove the wildcard expansion: %+v", rv)
	}
}

// ---------------------------------------------------------------------------
// RA6X-012 — NSEC3 delegation boundaries, opt-out semantics, unknown flags.
// ---------------------------------------------------------------------------

func TestRA6X012_NSEC3BoundariesAndOptOut(t *testing.T) {
	const zone = "example.com."
	p := nsec3Params{salt: "ABCD", iter: 1}

	t.Run("closest encloser at a signed delegation cannot deny below it", func(t *testing.T) {
		f := newLeafFixture(t, zone)
		// The review's example: a self-wrapping NSEC3 for child.example.com. with
		// NS and DS accepts x.child.example.com. as NXDOMAIN — it must not.
		rec := p.nsec3RR(t, zone, "child.example.com.", "child.example.com.", 0, dns.TypeNS, dns.TypeDS, dns.TypeRRSIG)
		rv := f.queryLeaf(t, "x.child.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, rec))
		if rv.DenialProof == nil || rv.DenialProof.Verified || !strings.Contains(rv.Error, "delegation point") {
			t.Fatalf("NSEC3 closest encloser at a delegation must be rejected: %+v", rv)
		}
		// Unsigned delegation as closest encloser (NS, no DS): same boundary.
		rec = p.nsec3RR(t, zone, "child.example.com.", "child.example.com.", 0, dns.TypeNS, dns.TypeRRSIG)
		rv = f.queryLeaf(t, "x.child.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, rec))
		if rv.DenialProof == nil || rv.DenialProof.Verified {
			t.Fatalf("NSEC3 closest encloser at an unsigned delegation must be rejected: %+v", rv)
		}
		// DNAME encloser.
		rec = p.nsec3RR(t, zone, "redir.example.com.", "redir.example.com.", 0, dns.TypeDNAME, dns.TypeRRSIG)
		rv = f.queryLeaf(t, "x.redir.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, rec))
		if rv.DenialProof == nil || rv.DenialProof.Verified || !strings.Contains(rv.Error, "DNAME") {
			t.Fatalf("NSEC3 closest encloser with DNAME must be rejected: %+v", rv)
		}
	})

	t.Run("opt-out NXDOMAIN is authenticated but insecure", func(t *testing.T) {
		f := newLeafFixture(t, zone)
		// The review's example: a signed self-wrapping apex NSEC3 with Flags=1.
		apex := p.nsec3RR(t, zone, zone, zone, NSEC3FlagOptOut, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeDNSKEY)
		rv := f.queryLeaf(t, "nx.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, apex))
		if rv.DenialProof == nil || !rv.DenialProof.Verified {
			t.Fatalf("opt-out NXDOMAIN proof must verify cryptographically: %+v", rv)
		}
		if !rv.DenialProof.OptOut || rv.DenialProof.NextCloser != "nx.example.com." {
			t.Fatalf("opt-out must be reported with the next closer name: %+v", rv.DenialProof)
		}
		verdict, msg := recordValidationVerdict(rv)
		if verdict != StatusInsecure || !strings.Contains(msg, "opt-out") {
			t.Fatalf("opt-out NXDOMAIN verdict = %s (%s), want insecure", verdict, msg)
		}
		// The same proof without opt-out is secure.
		apexPlain := p.nsec3RR(t, zone, zone, zone, 0, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeDNSKEY)
		rv = f.queryLeaf(t, "nx.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, apexPlain))
		if rv.DenialProof == nil || !rv.DenialProof.Verified || rv.DenialProof.OptOut {
			t.Fatalf("non-opt-out NXDOMAIN must verify without opt-out: %+v", rv)
		}
		if verdict, _ := recordValidationVerdict(rv); verdict != StatusSecure {
			t.Fatalf("verdict = %s, want secure", verdict)
		}
	})

	t.Run("wildcard answer with opt-out next-closer cover is insecure", func(t *testing.T) {
		f := newLeafFixture(t, zone)
		w := &dns.A{Hdr: rrHdr("*.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.3")}
		sig := f.zone.signZSK(t, w)
		sig.Hdr.Name = "foo.example.com."
		answer := []dns.RR{&dns.A{Hdr: rrHdr("foo.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.3")}, sig}
		optOutCover := p.nsec3RR(t, zone, zone, zone, NSEC3FlagOptOut, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeDNSKEY)
		rv := f.queryLeaf(t, "foo.example.com.", dns.TypeA, dns.RcodeSuccess, answer, f.zone.signedAuthority(t, optOutCover))
		if !rv.Wildcard || !rv.WildcardProofVerified || !rv.WildcardProof.OptOut {
			t.Fatalf("wildcard proof with opt-out cover must verify and report opt-out: %+v err=%s", rv.WildcardProof, rv.Error)
		}
		if verdict, _ := recordValidationVerdict(rv); verdict != StatusInsecure {
			t.Fatalf("verdict = %s, want insecure", verdict)
		}
		plainCover := p.nsec3RR(t, zone, zone, zone, 0, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeDNSKEY)
		rv = f.queryLeaf(t, "foo.example.com.", dns.TypeA, dns.RcodeSuccess, answer, f.zone.signedAuthority(t, plainCover))
		if verdict, _ := recordValidationVerdict(rv); verdict != StatusSecure {
			t.Fatalf("verdict = %s, want secure for a non-opt-out cover (%s)", verdict, rv.Error)
		}
	})

	t.Run("unknown NSEC3 flag bits are ignored", func(t *testing.T) {
		f := newLeafFixture(t, zone)
		for _, flags := range []uint8{2, 3} {
			apex := p.nsec3RR(t, zone, zone, zone, flags, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeDNSKEY)
			rv := f.queryLeaf(t, "nx.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, apex))
			if rv.DenialProof == nil || rv.DenialProof.Verified {
				t.Fatalf("flags=%d: a record with unknown flag bits must not prove anything: %+v", flags, rv)
			}
			if !strings.Contains(rv.Error, "unknown flag bits") {
				t.Fatalf("flags=%d: expected the unknown-flags reason, got %q", flags, rv.Error)
			}
		}
	})

	t.Run("opt-out DS absence needs a complete closest-encloser proof", func(t *testing.T) {
		v := &Validator{}
		parent := newTestZone(t, zone)
		const child = "sub.example.com."
		build := func(rrs ...dns.RR) *dnspkg.QueryResult {
			msg := new(dns.Msg)
			msg.SetQuestion(child, dns.TypeDS)
			msg.Ns = parent.signedAuthority(t, rrs...)
			raw, err := msg.Pack()
			if err != nil {
				t.Fatalf("pack: %v", err)
			}
			qr := &dnspkg.QueryResult{RCode: dns.RcodeSuccess, RawResponse: raw}
			for _, rr := range rrs {
				if n, ok := rr.(*dns.NSEC3); ok {
					qr.NSEC3 = append(qr.NSEC3, dnspkg.NSEC3FromRR(n, dnspkg.SectionAuthority))
				}
			}
			return qr
		}
		// Incomplete: an opt-out record covers H(child) but nothing matches the
		// closest encloser (the apex).
		cover := p.nsec3RRHashed(t, zone, strings.Repeat("0", 32), strings.Repeat("V", 32), NSEC3FlagOptOut, dns.TypeA)
		if proof, ok := v.verifyDSAbsence(child, zone, parent.keyRecords(), build(cover)); ok {
			t.Fatalf("opt-out cover without a closest-encloser match must not prove DS absence: %+v", proof)
		}
		// Complete: apex matches (closest encloser) and an opt-out record covers
		// the next closer name (the child itself) → insecure delegation. The
		// chain is consistent: [lowest → H(apex)), [H(apex) → H(apex)+1),
		// [H(apex)+1 → highest), so exactly one record covers H(child).
		hApex := p.hashOf(t, zone)
		lowest, highest := strings.Repeat("0", 32), strings.Repeat("V", 32)
		apex := p.nsec3RRHashed(t, zone, hApex, bumpHash(hApex), 0, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeDNSKEY)
		chain := func(flags uint8) []dns.RR {
			return []dns.RR{
				p.nsec3RRHashed(t, zone, lowest, hApex, flags, dns.TypeA),
				apex,
				p.nsec3RRHashed(t, zone, bumpHash(hApex), highest, flags, dns.TypeA),
			}
		}
		proof, ok := v.verifyDSAbsence(child, zone, parent.keyRecords(), build(chain(NSEC3FlagOptOut)...))
		if !ok || !proof.OptOut || proof.ClosestEncloser != zone || proof.NextCloser != child {
			t.Fatalf("complete opt-out proof must verify as insecure delegation: ok=%v %+v", ok, proof)
		}
		// The same closest-encloser proof with NON-opt-out covers proves the
		// child does not exist at all — not an unsigned delegation.
		if proof, ok := v.verifyDSAbsence(child, zone, parent.keyRecords(), build(chain(0)...)); ok {
			t.Fatalf("non-opt-out cover must not prove an unsigned delegation: %+v", proof)
		}
		// Signed delegation (matching record with the DS bit) is not DS absence.
		signedDeleg := p.nsec3RR(t, zone, child, "zzz.example.com.", 0, dns.TypeNS, dns.TypeDS, dns.TypeRRSIG)
		if proof, ok := v.verifyDSAbsence(child, zone, parent.keyRecords(), build(signedDeleg)); ok || !strings.Contains(proof.Error, "DS bit set") {
			t.Fatalf("matching NSEC3 with the DS bit must not prove DS absence: ok=%v %+v", ok, proof)
		}
		// Unsigned delegation (matching record, NS without DS) is DS absence, secure.
		unsignedDeleg := p.nsec3RR(t, zone, child, "zzz.example.com.", 0, dns.TypeNS, dns.TypeRRSIG)
		if proof, ok := v.verifyDSAbsence(child, zone, parent.keyRecords(), build(unsignedDeleg)); !ok || proof.OptOut {
			t.Fatalf("matching delegation NSEC3 without DS must prove an insecure delegation without opt-out: ok=%v %+v", ok, proof)
		}
	})
}

// ---------------------------------------------------------------------------
// RA6X-013 — wildcard and DS-absence proofs must not combine NSEC3 chains.
// ---------------------------------------------------------------------------

func TestRA6X013_NoCrossChainNSEC3Evidence(t *testing.T) {
	const zone = "example.com."
	const qname = "foo.example.com."
	pEmpty := nsec3Params{salt: "", iter: 0}
	pAA := nsec3Params{salt: "AA", iter: 0}
	pIter := nsec3Params{salt: "", iter: 3}

	// The review's probe: two self-wrapping records, each owned by H(foo) in
	// its own chain. Each alone cannot deny foo; together they must not either.
	recEmpty := pEmpty.nsec3RR(t, zone, qname, qname, 0, dns.TypeA)
	recAA := pAA.nsec3RR(t, zone, qname, qname, 0, dns.TypeA)
	recIter := pIter.nsec3RR(t, zone, qname, qname, 0, dns.TypeA)
	toRecs := func(rrs ...*dns.NSEC3) []dnspkg.NSEC3Record {
		out := make([]dnspkg.NSEC3Record, 0, len(rrs))
		for _, r := range rrs {
			out = append(out, dnspkg.NSEC3FromRR(r, dnspkg.SectionAuthority))
		}
		return out
	}
	for name, set := range map[string][]*dns.NSEC3{
		"empty salt alone":     {recEmpty},
		"AA salt alone":        {recAA},
		"union":                {recEmpty, recAA},
		"union reversed":       {recAA, recEmpty},
		"different iterations": {recEmpty, recIter},
		"all three":            {recAA, recIter, recEmpty},
	} {
		if proof := VerifyWildcardDenial(qname, 2, nil, toRecs(set...)); proof.Verified {
			t.Fatalf("%s: wildcard denial must fail, got %+v", name, proof)
		}
	}

	// Signed end-to-end through the wildcard path.
	f := newLeafFixture(t, zone)
	w := &dns.A{Hdr: rrHdr("*.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.3")}
	sig := f.zone.signZSK(t, w)
	sig.Hdr.Name = qname
	answer := []dns.RR{&dns.A{Hdr: rrHdr(qname, dns.TypeA), A: net.ParseIP("192.0.2.3")}, sig}
	for name, set := range map[string][]dns.RR{
		"union":          {recEmpty, recAA},
		"union reversed": {recAA, recEmpty},
	} {
		rv := f.queryLeaf(t, qname, dns.TypeA, dns.RcodeSuccess, answer, f.zone.signedAuthority(t, set...))
		if rv.WildcardProofVerified {
			t.Fatalf("%s: signed cross-chain union must not prove the wildcard expansion: %+v", name, rv.WildcardProof)
		}
	}

	// DS absence: the parameter-selection defect. Chain 1 (empty salt) has a
	// self-wrapping record at H1(sub); chain 2 (salt AA) covers everything but
	// its own owner. Neither proves DS absence for sub; nor does the union.
	v := &Validator{}
	parent := newTestZone(t, zone)
	const child = "sub.example.com."
	dsBuild := func(rrs ...dns.RR) *dnspkg.QueryResult {
		msg := new(dns.Msg)
		msg.SetQuestion(child, dns.TypeDS)
		msg.Ns = parent.signedAuthority(t, rrs...)
		raw, err := msg.Pack()
		if err != nil {
			t.Fatalf("pack: %v", err)
		}
		qr := &dnspkg.QueryResult{RCode: dns.RcodeSuccess, RawResponse: raw}
		for _, rr := range rrs {
			if n, ok := rr.(*dns.NSEC3); ok {
				qr.NSEC3 = append(qr.NSEC3, dnspkg.NSEC3FromRR(n, dnspkg.SectionAuthority))
			}
		}
		return qr
	}
	selfEmpty := pEmpty.nsec3RR(t, zone, child, child, NSEC3FlagOptOut, dns.TypeA)
	selfAA := pAA.nsec3RR(t, zone, child, child, NSEC3FlagOptOut, dns.TypeA)
	for name, set := range map[string][]dns.RR{
		"chain 1 alone":  {selfEmpty},
		"chain 2 alone":  {selfAA},
		"union":          {selfEmpty, selfAA},
		"union reversed": {selfAA, selfEmpty},
	} {
		if proof, ok := v.verifyDSAbsence(child, zone, parent.keyRecords(), dsBuild(set...)); ok {
			t.Fatalf("DS absence %s: must not verify across chains, got %+v", name, proof)
		}
	}

	// A complete valid chain beside an incomplete transition chain works in
	// either order (NXDOMAIN through the leaf path).
	apexEmpty := pEmpty.nsec3RR(t, zone, zone, zone, 0, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeDNSKEY)
	partialAA := pAA.nsec3RR(t, zone, "other.example.com.", "other.example.com.", 0, dns.TypeA)
	for name, set := range map[string][]dns.RR{
		"complete first":  {apexEmpty, partialAA},
		"complete second": {partialAA, apexEmpty},
	} {
		rv := f.queryLeaf(t, "nx.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, set...))
		if rv.DenialProof == nil || !rv.DenialProof.Verified {
			t.Fatalf("%s: the complete chain must prove NXDOMAIN regardless of order: %+v", name, rv)
		}
	}
}
