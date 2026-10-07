package validator

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// RM51X-006: RFC 1034 §4.3.2 / RFC 2308 §2.1 let a server answer a query
// whose CNAME chain ends at a nonexistent name with NXDOMAIN and the signed
// CNAME in the Answer section; the RCODE and the denial records describe the
// chain's final name. The validator used to treat the whole response as a
// denial of the queried name, which exists, and reported bogus.

func rm51x006Hop(t *testing.T, res *ValidationResult) *CNAMEChainResult {
	t.Helper()
	if len(res.CNAMEChains) != 1 {
		t.Fatalf("expected one alias hop, got %d (verdict %s, errors %v)", len(res.CNAMEChains), res.Result, res.Errors)
	}
	return &res.CNAMEChains[0]
}

func rm51x006TargetDenial(t *testing.T, hop *CNAMEChainResult) *NSECProof {
	t.Helper()
	for i := range hop.Chain {
		if rv := hop.Chain[i].RecordValidation; rv != nil && rv.DenialProof != nil {
			return rv.DenialProof
		}
	}
	t.Fatalf("alias target %s carries no denial proof: %+v", hop.Target, hop)
	return nil
}

// A dangling CNAME inside a signed zone: NXDOMAIN, signed CNAME in Answer,
// the apex NSEC (which covers the target) in Authority.
func TestRM51X006_DanglingCNAMEWithNXDOMAINIsSecure(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	cname := &dns.CNAME{Hdr: rrHdr("www.child.test.", dns.TypeCNAME), Target: "dead.child.test."}
	apex := nsecRR("child.test.", "www.child.test.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY)
	authority := child.signedAuthority(t, apex)
	f.m.respond("www.child.test.", dns.TypeA, dns.RcodeNameError, []dns.RR{cname, child.signZSK(t, cname)}, authority, nil)
	f.m.respond("dead.child.test.", dns.TypeA, dns.RcodeNameError, nil, authority, nil)

	res := f.validate(t, "www.child.test.")
	if res.Result != StatusSecure {
		t.Fatalf("verdict %s, want secure (errors %v)", res.Result, res.Errors)
	}
	leaf := res.Chain[len(res.Chain)-1]
	if leaf.RecordValidation == nil || !leaf.RecordValidation.RRSIGVerified || leaf.RecordValidation.RecordType != "CNAME" || leaf.RecordValidation.Target != "dead.child.test." {
		t.Fatalf("queried name must authenticate as a CNAME alias: %+v", leaf.RecordValidation)
	}
	if leaf.RecordValidation.DenialProof != nil {
		t.Fatalf("no denial must be evaluated for the queried name itself: %+v", leaf.RecordValidation.DenialProof)
	}
	hop := rm51x006Hop(t, res)
	if hop.Target != "dead.child.test." || hop.Result != StatusSecure {
		t.Fatalf("alias hop = %s -> %s %s (%s)", hop.Source, hop.Target, hop.Result, hop.Error)
	}
	if proof := rm51x006TargetDenial(t, hop); !proof.Verified {
		t.Fatalf("target's NXDOMAIN must be proven on its own hop: %+v", proof)
	}
}

// The DNAME flavour: the synthesized CNAME points into a target tree that
// lacks the name, answered NXDOMAIN with the DNAME and the synthesized CNAME
// in Answer.
func TestRM51X006_DanglingDNAMEWithNXDOMAINIsSecure(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	dname := &dns.DNAME{Hdr: rrHdr("old.child.test.", dns.TypeDNAME), Target: "new.child.test."}
	synth := &dns.CNAME{Hdr: rrHdr("www.old.child.test.", dns.TypeCNAME), Target: "www.new.child.test."}
	// NSEC chain: apex -> old.child.test. -> apex. www.new.child.test. and
	// *.child.test. both fall in the apex interval.
	apex := nsecRR("child.test.", "old.child.test.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY)
	authority := child.signedAuthority(t, apex)
	f.m.respond("www.old.child.test.", dns.TypeA, dns.RcodeNameError, []dns.RR{dname, child.signZSK(t, dname), synth}, authority, nil)
	f.m.respond("www.new.child.test.", dns.TypeA, dns.RcodeNameError, nil, authority, nil)

	res := f.validate(t, "www.old.child.test.")
	if res.Result != StatusSecure {
		t.Fatalf("verdict %s, want secure (errors %v)", res.Result, res.Errors)
	}
	leaf := res.Chain[len(res.Chain)-1]
	if leaf.RecordValidation == nil || !leaf.RecordValidation.RRSIGVerified || leaf.RecordValidation.RecordType != "DNAME" || leaf.RecordValidation.Target != "www.new.child.test." {
		t.Fatalf("queried name must authenticate as a DNAME redirection: %+v", leaf.RecordValidation)
	}
	hop := rm51x006Hop(t, res)
	if hop.Target != "www.new.child.test." || hop.Result != StatusSecure {
		t.Fatalf("alias hop = %s -> %s %s (%s)", hop.Source, hop.Target, hop.Result, hop.Error)
	}
	if proof := rm51x006TargetDenial(t, hop); !proof.Verified {
		t.Fatalf("target's NXDOMAIN must be proven on its own hop: %+v", proof)
	}
}

// An unsigned alias in an NXDOMAIN response is still an alias answer and
// still fails: the CNAME RRset must authenticate, so the verdict is bogus.
func TestRM51X006_UnsignedCNAMEWithNXDOMAINStaysBogus(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	cname := &dns.CNAME{Hdr: rrHdr("www.child.test.", dns.TypeCNAME), Target: "dead.child.test."}
	apex := nsecRR("child.test.", "www.child.test.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY)
	authority := child.signedAuthority(t, apex)
	f.m.respond("www.child.test.", dns.TypeA, dns.RcodeNameError, []dns.RR{cname}, authority, nil)
	f.m.respond("dead.child.test.", dns.TypeA, dns.RcodeNameError, nil, authority, nil)

	res := f.validate(t, "www.child.test.")
	if res.Result != StatusBogus {
		t.Fatalf("verdict %s, want bogus for an unsigned alias", res.Result)
	}
	if len(res.CNAMEChains) != 0 {
		t.Fatalf("an unauthenticated alias must not be followed: %+v", res.CNAMEChains)
	}
	joined := strings.Join(res.Errors, "; ")
	if !strings.Contains(joined, "CNAME RRSIG verification failed") {
		t.Fatalf("errors should name the CNAME signature failure, got %q", joined)
	}
}

// A CNAME owned by some other name does not turn an NXDOMAIN for the queried
// name into an alias answer; the denial is evaluated for the queried name.
func TestRM51X006_StrayCNAMEAtOtherOwnerKeepsDenialPath(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	stray := &dns.CNAME{Hdr: rrHdr("other.child.test.", dns.TypeCNAME), Target: "dead.child.test."}
	apex := nsecRR("child.test.", "www.child.test.", dns.TypeNS, dns.TypeSOA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY)
	authority := child.signedAuthority(t, apex)
	f.m.respond("nx.child.test.", dns.TypeA, dns.RcodeNameError, []dns.RR{stray}, authority, nil)

	res := f.validate(t, "nx.child.test.")
	if res.Result != StatusSecure {
		t.Fatalf("verdict %s, want secure NXDOMAIN (errors %v)", res.Result, res.Errors)
	}
	leaf := res.Chain[len(res.Chain)-1]
	if leaf.RecordValidation == nil || leaf.RecordValidation.DenialProof == nil || !leaf.RecordValidation.DenialProof.Verified {
		t.Fatalf("queried name's NXDOMAIN must be proven: %+v", leaf.RecordValidation)
	}
	if len(res.CNAMEChains) != 0 {
		t.Fatalf("a CNAME at another owner must not be followed: %+v", res.CNAMEChains)
	}
}
