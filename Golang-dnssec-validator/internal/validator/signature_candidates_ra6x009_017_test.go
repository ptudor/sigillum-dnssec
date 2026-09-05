package validator

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// RA6X-009 (High): the wildcard decision must use the Labels field of the
// signature that actually verified. An attacker who replays a genuine
// wildcard signature and prepends an invalid one claiming an exact-name
// answer (Labels = owner label count) must not be able to skip the required
// no-exact-match proof.

// forgedCopy returns a copy of sig with the given Labels/SignerName and a
// garbage signature body.
func forgedCopy(sig *dns.RRSIG, labels uint8, signer string) *dns.RRSIG {
	f := dns.Copy(sig).(*dns.RRSIG)
	f.Labels = labels
	if signer != "" {
		f.SignerName = signer
	}
	junk := make([]byte, 64)
	for i := range junk {
		junk[i] = byte(i*7 + 3)
	}
	f.Signature = base64.StdEncoding.EncodeToString(junk)
	return f
}

func TestRA6X009_WildcardMetadataComesFromVerifiedSignature(t *testing.T) {
	m := newMockDNS(t)
	zone := newTestZone(t, "child.test.")
	m.serveInfra("child.test.")

	// A wildcard *.child.test. A expanded to www.child.test.: the signature is
	// computed over the wildcard-owned RRset (Labels = 2) and served with the
	// expanded owner, exactly as an authoritative server does (RFC 4034 §3.1.3).
	wild := &dns.A{Hdr: rrHdr("*.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.7")}
	realSig := zone.signZSK(t, wild)
	realSig.Hdr.Name = "www.child.test."
	expanded := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.7")}
	if realSig.Labels != 2 {
		t.Fatalf("wildcard signature Labels = %d, want 2", realSig.Labels)
	}
	forgedExact := forgedCopy(realSig, 3, "")
	forgedSigner := forgedCopy(realSig, 3, "other.test.")

	// The wildcard's own NSEC proves www.child.test. has no exact match.
	nsec := &dns.NSEC{Hdr: rrHdr("*.child.test.", dns.TypeNSEC), NextDomain: "zzz.child.test.", TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}}
	nsecSig := zone.signZSK(t, nsec)

	v := m.newValidator()
	run := func(answer, authority []dns.RR) *RecordValidation {
		t.Helper()
		m.respond("www.child.test.", dns.TypeA, dns.RcodeSuccess, answer, authority, nil)
		return v.verifyActualRecord(testCtx(t), "www.child.test.", "child.test.", zone.keyRecords())
	}

	orders := map[string][]dns.RR{
		"forged exact-name sig first":   {expanded, forgedExact, realSig},
		"forged exact-name sig last":    {expanded, realSig, forgedExact},
		"forged signer first":           {expanded, forgedSigner, realSig},
		"both forgeries around genuine": {expanded, forgedExact, realSig, forgedSigner},
	}
	for name, answer := range orders {
		t.Run(name+" without proof", func(t *testing.T) {
			rv := run(answer, nil)
			if !rv.RRSIGVerified {
				t.Fatalf("genuine wildcard signature must verify: %+v", rv)
			}
			if !rv.Wildcard || rv.WildcardSource != "*.child.test." {
				t.Fatalf("wildcard synthesis must be detected from the verified signature: %+v", rv)
			}
			if rv.WildcardProofVerified {
				t.Fatal("no NSEC proof was served; it must not be reported verified")
			}
			if verdict, _ := recordValidationVerdict(rv); verdict != StatusBogus {
				t.Fatalf("wildcard answer without a no-exact-match proof must be bogus, got %s", verdict)
			}
		})
		t.Run(name+" with proof", func(t *testing.T) {
			rv := run(answer, []dns.RR{nsec, nsecSig})
			if !rv.RRSIGVerified || !rv.Wildcard || !rv.WildcardProofVerified {
				t.Fatalf("authentic wildcard answer with proof must verify: %+v", rv)
			}
			if rv.SigningKeyTag != zone.zsk.KeyTag() {
				t.Fatalf("SigningKeyTag = %d, want the verified signature's key %d", rv.SigningKeyTag, zone.zsk.KeyTag())
			}
			if verdict, _ := recordValidationVerdict(rv); verdict != StatusSecure {
				t.Fatalf("verdict = %s, want secure", verdict)
			}
		})
	}

	// An ordinary exact-name answer with a valid signature stays secure and is
	// not a wildcard.
	exact := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.8")}
	rv := run([]dns.RR{exact, zone.signZSK(t, exact)}, nil)
	if !rv.RRSIGVerified || rv.Wildcard {
		t.Fatalf("exact-name answer must verify and not be flagged as wildcard: %+v", rv)
	}
	// A forged wildcard-claiming signature beside a genuine exact-name one must
	// not turn an exact answer into a wildcard either.
	forgedWild := forgedCopy(zone.signZSK(t, exact), 2, "")
	rv = run([]dns.RR{exact, forgedWild, zone.signZSK(t, exact)}, nil)
	if !rv.RRSIGVerified || rv.Wildcard {
		t.Fatalf("forged Labels on an unverified signature must not mark the answer wildcard: %+v", rv)
	}
}

// RA6X-017 (Medium): every eligible covering signature is tried as a whole. An
// expired, unknown-key or invalid first signature must not reject an RRset
// that a later valid signature authenticates, under A, CNAME, NSEC and NSEC3.
func TestRA6X017_AlternativeSignaturesAreTried(t *testing.T) {
	m := newMockDNS(t)
	zone := newTestZone(t, "child.test.")
	// A second ZSK with a different tag, so signatures name different keys.
	zsk2, zsk2Signer := genSigningKey(t, zone.name, 256)
	keys := append(zone.keyRecords(), dnspkg.DNSKEYFromRR(zsk2, dnspkg.SectionAnswer))
	m.serveInfra("child.test.")
	v := m.newValidator()

	expiredSig := func(rrs ...dns.RR) *dns.RRSIG {
		s := signWith(t, zone.name, zone.zsk, zone.zskSigner, rrs)
		s.Expiration = uint32(time.Now().Add(-48 * time.Hour).Unix())
		s.Inception = uint32(time.Now().Add(-72 * time.Hour).Unix())
		if err := s.Sign(zone.zskSigner, rrs); err != nil {
			t.Fatalf("sign expired: %v", err)
		}
		return s
	}
	unknownKeySig := func(rrs ...dns.RR) *dns.RRSIG {
		stranger, strangerSigner := genSigningKey(t, zone.name, 256)
		return signWith(t, zone.name, stranger, strangerSigner, rrs)
	}
	validSig := func(rrs ...dns.RR) *dns.RRSIG {
		return signWith(t, zone.name, zsk2, zsk2Signer, rrs)
	}

	// --- A ---
	a := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	for name, sigs := range map[string][]dns.RR{
		"expired then valid":           {expiredSig(a), validSig(a)},
		"unknown key then valid":       {unknownKeySig(a), validSig(a)},
		"expired, unknown, then valid": {expiredSig(a), unknownKeySig(a), validSig(a)},
		"valid first":                  {validSig(a), expiredSig(a), unknownKeySig(a)},
		"invalid bytes then valid":     {forgedCopy(validSig(a), 3, ""), validSig(a)},
	} {
		m.respond("www.child.test.", dns.TypeA, dns.RcodeSuccess, append([]dns.RR{a}, sigs...), nil, nil)
		rv := v.verifyActualRecord(testCtx(t), "www.child.test.", "child.test.", keys)
		if !rv.RRSIGVerified || rv.SigningKeyTag != zsk2.KeyTag() {
			t.Fatalf("A/%s: RRset with a valid alternative signature must verify via it: %+v", name, rv)
		}
	}
	// No valid alternative at all: still bogus.
	m.respond("www.child.test.", dns.TypeA, dns.RcodeSuccess, []dns.RR{a, expiredSig(a), unknownKeySig(a)}, nil, nil)
	if rv := v.verifyActualRecord(testCtx(t), "www.child.test.", "child.test.", keys); rv.RRSIGVerified {
		t.Fatalf("A with only expired/unknown-key signatures must not verify: %+v", rv)
	}

	// --- CNAME ---
	cname := &dns.CNAME{Hdr: rrHdr("alias.child.test.", dns.TypeCNAME), Target: "www.child.test."}
	m.respond("alias.child.test.", dns.TypeA, dns.RcodeSuccess, []dns.RR{cname, expiredSig(cname), validSig(cname)}, nil, nil)
	rv := v.verifyActualRecord(testCtx(t), "alias.child.test.", "child.test.", keys)
	if !rv.RRSIGVerified || rv.RecordType != "CNAME" || rv.SigningKeyTag != zsk2.KeyTag() {
		t.Fatalf("CNAME with expired-then-valid signatures must verify via the valid one: %+v", rv)
	}

	// --- NSEC (NXDOMAIN) ---
	nsec := &dns.NSEC{Hdr: rrHdr("child.test.", dns.TypeNSEC), NextDomain: "zzz.child.test.", TypeBitMap: []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY}}
	m.respond("nx.child.test.", dns.TypeA, dns.RcodeNameError, nil, []dns.RR{nsec, expiredSig(nsec), unknownKeySig(nsec), validSig(nsec)}, nil)
	rv = v.verifyActualRecord(testCtx(t), "nx.child.test.", "child.test.", keys)
	if rv.DenialProof == nil || !rv.DenialProof.Verified || !rv.RRSIGVerified {
		t.Fatalf("NSEC NXDOMAIN with expired-first signatures must verify via the valid one: %+v", rv)
	}
	m.respond("nx.child.test.", dns.TypeA, dns.RcodeNameError, nil, []dns.RR{nsec, expiredSig(nsec)}, nil)
	rv = v.verifyActualRecord(testCtx(t), "nx.child.test.", "child.test.", keys)
	if rv.DenialProof == nil || rv.DenialProof.Verified || !strings.Contains(rv.Error, "validity period") {
		t.Fatalf("NSEC signed only by an expired signature must fail with the time reason: %+v", rv)
	}

	// --- NSEC3 (NODATA) ---
	salt := []byte{0xab, 0xcd}
	qname := "nodata.child.test."
	hashed := computeNSEC3Hash(qname, salt, 0)
	nsec3 := &dns.NSEC3{
		Hdr:        rrHdr(strings.ToLower(hashed)+".child.test.", dns.TypeNSEC3),
		Hash:       NSEC3HashSHA1,
		Flags:      0,
		Iterations: 0,
		SaltLength: uint8(len(salt)),
		Salt:       "ABCD",
		HashLength: 20,
		NextDomain: computeNSEC3Hash("zz.child.test.", salt, 0),
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
	}
	v.SetQueryType(dns.TypeAAAA)
	m.respond(qname, dns.TypeAAAA, dns.RcodeSuccess, nil, []dns.RR{nsec3, expiredSig(nsec3), validSig(nsec3)}, nil)
	rv = v.verifyActualRecord(testCtx(t), qname, "child.test.", keys)
	if rv.DenialProof == nil || !rv.DenialProof.Verified {
		t.Fatalf("NSEC3 NODATA with expired-first signatures must verify via the valid one: %+v", rv)
	}
}

// RA6X-017: an authenticated DS RRset containing only unsupported algorithms or
// digest types has no supported authentication path and is insecure, not bogus;
// a supported path that fails stays bogus, and an unknown extra DS never
// downgrades a broken supported chain.
func TestRA6X017_UnsupportedDSClassification(t *testing.T) {
	newFixture := func(t *testing.T) *ra6x007Fixture {
		t.Helper()
		return newRA6X007Fixture(t)
	}
	unsupportedDS := func(owner string) *dns.DS {
		return &dns.DS{Hdr: rrHdr(owner, dns.TypeDS), KeyTag: 4242, Algorithm: dns.ED448, DigestType: 2, Digest: strings.Repeat("ab", 32)}
	}
	unsupportedDigest := func(owner string) *dns.DS {
		return &dns.DS{Hdr: rrHdr(owner, dns.TypeDS), KeyTag: 4243, Algorithm: dns.ECDSAP256SHA256, DigestType: 3, Digest: strings.Repeat("cd", 32)}
	}
	serveDSSet := func(t *testing.T, f *ra6x007Fixture, set ...dns.RR) {
		t.Helper()
		sig := f.parent.signZSK(t, set...)
		f.m.respond("child.test.", dns.TypeDS, dns.RcodeSuccess, append(set, sig), nil, nil)
	}

	t.Run("only unsupported DS is insecure", func(t *testing.T) {
		f := newFixture(t)
		serveDSSet(t, f, unsupportedDS("child.test."), unsupportedDigest("child.test."))
		f.genuine.serveDNSKEY(t, f.m)
		zr := f.validateChild(t)
		if zr.Status != StatusInsecure {
			t.Fatalf("only-unsupported DS must be insecure, got %s errors=%v", zr.Status, zr.Errors)
		}
		if !strings.Contains(strings.Join(zr.Warnings, "\n"), "no supported authentication path") {
			t.Fatalf("expected an unsupported-path warning, got %v", zr.Warnings)
		}
	})
	t.Run("mixed with a good supported path is secure", func(t *testing.T) {
		f := newFixture(t)
		serveDSSet(t, f, unsupportedDS("child.test."), f.genuine.ds(t))
		f.genuine.serveDNSKEY(t, f.m)
		zr := f.validateChild(t)
		if zr.Status != StatusSecure {
			t.Fatalf("supported DS beside an unsupported one must be secure, got %s errors=%v", zr.Status, zr.Errors)
		}
	})
	t.Run("broken supported path stays bogus despite unsupported extra DS", func(t *testing.T) {
		f := newFixture(t)
		wrong := f.genuine.ds(t)
		wrong.Digest = strings.Repeat("00", 32)
		serveDSSet(t, f, unsupportedDS("child.test."), wrong)
		f.genuine.serveDNSKEY(t, f.m)
		zr := f.validateChild(t)
		if zr.Status != StatusBogus {
			t.Fatalf("a broken supported path must be bogus, got %s", zr.Status)
		}
	})
	t.Run("unsupported DS that was not authenticated cannot downgrade", func(t *testing.T) {
		f := newFixture(t)
		// Genuine signed DS for the real key; the unsupported DS rides unsigned
		// in Additional. The chain is secure and the extra DS is ignored.
		f.parent.serveDS(t, f.m, f.genuine, nil, []dns.RR{unsupportedDS("child.test.")})
		f.genuine.serveDNSKEY(t, f.m)
		zr := f.validateChild(t)
		if zr.Status != StatusSecure {
			t.Fatalf("expected secure, got %s errors=%v", zr.Status, zr.Errors)
		}
	})
	t.Run("supported classification helpers", func(t *testing.T) {
		sup, unsup := SupportedDSRecords([]dnspkg.DSRecord{
			{KeyTag: 1, Algorithm: 13, DigestType: 2},
			{KeyTag: 2, Algorithm: 16, DigestType: 2},
			{KeyTag: 3, Algorithm: 13, DigestType: 3},
			{KeyTag: 4, Algorithm: 8, DigestType: 4},
		})
		if len(sup) != 2 || sup[0].KeyTag != 1 || sup[1].KeyTag != 4 || len(unsup) != 2 {
			t.Fatalf("SupportedDSRecords = %+v / %+v", sup, unsup)
		}
	})
}
