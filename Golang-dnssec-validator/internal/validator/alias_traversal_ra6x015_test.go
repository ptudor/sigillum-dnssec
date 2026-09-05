package validator

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// RA6X-015 (High): alias traversal follows exactly the CNAME/DNAME target
// that leaf verification authenticated; a hop that cannot be validated is
// indeterminate, unrelated CNAMEs are ignored, and an explicit CNAME query
// completes once its RRset is authenticated.

// serveAlias serves alias → target as a signed CNAME in zone.
func serveAlias(t *testing.T, m *mockDNS, z *testZone, alias, target string) {
	t.Helper()
	c := &dns.CNAME{Hdr: rrHdr(alias, dns.TypeCNAME), Target: dns.Fqdn(target)}
	m.answer(alias, dns.TypeA, c, z.signZSK(t, c))
}

// serveA serves a signed A record in zone.
func serveA(t *testing.T, m *mockDNS, z *testZone, name string) {
	t.Helper()
	a := &dns.A{Hdr: rrHdr(name, dns.TypeA), A: net.ParseIP("192.0.2.42")}
	m.answer(name, dns.TypeA, a, z.signZSK(t, a))
}

func TestRA6X015_AliasToBogusTargetNeverSecure(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	// other.test. is delegated but serves a DNSKEY RRset signed by a stranger.
	other := f.addChild(t, "other.test.")
	stranger := newTestZone(t, "other.test.")
	f.m.answer("other.test.", dns.TypeDNSKEY, append(other.dnskeyRRset(), stranger.signKSK(t, other.dnskeyRRset()...))...)
	serveAlias(t, f.m, child, "alias.child.test.", "www.other.test.")
	serveA(t, f.m, other, "www.other.test.")

	res := f.validate(t, "alias.child.test.")
	if res.Result != StatusBogus {
		t.Fatalf("alias to a bogus target must be bogus, got %s errors=%v", res.Result, res.Errors)
	}
	if len(res.CNAMEChains) != 1 || res.CNAMEChains[0].Target != "www.other.test." || res.CNAMEChains[0].Result != StatusBogus {
		t.Fatalf("CNAME chain = %+v", res.CNAMEChains)
	}

	// Drop the target's DNSKEY replies: the hop cannot be validated and the
	// final status is indeterminate, never secure.
	f2 := newChainFixture(t)
	f2.useTimeout(300 * time.Millisecond)
	child2 := f2.addChild(t, "child.test.")
	other2 := f2.addChild(t, "other.test.")
	serveAlias(t, f2.m, child2, "alias.child.test.", "www.other.test.")
	serveA(t, f2.m, other2, "www.other.test.")
	f2.m.drop("other.test.", dns.TypeDNSKEY)
	res = f2.validate(t, "alias.child.test.")
	if res.Result != StatusIndeterminate {
		t.Fatalf("alias whose target replies are dropped must be indeterminate, got %s", res.Result)
	}
	if len(res.CNAMEChains) != 1 || res.CNAMEChains[0].Result != StatusIndeterminate {
		t.Fatalf("CNAME chain = %+v", res.CNAMEChains)
	}
}

func TestRA6X015_FollowsAuthenticatedTargetNotRediscovery(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	good := f.addChild(t, "good.test.")
	bad := f.addChild(t, "bad.test.")
	stranger := newTestZone(t, "bad.test.")
	f.m.answer("bad.test.", dns.TypeDNSKEY, append(bad.dnskeyRRset(), stranger.signKSK(t, bad.dnskeyRRset()...))...)
	serveA(t, f.m, good, "www.good.test.")
	serveA(t, f.m, bad, "www.bad.test.")

	// The server answers the alias with a signed CNAME to the bogus target the
	// first time and to the good target afterwards (a switching server). The
	// authenticated first answer is what must be followed.
	toBad := &dns.CNAME{Hdr: rrHdr("alias.child.test.", dns.TypeCNAME), Target: "www.bad.test."}
	toGood := &dns.CNAME{Hdr: rrHdr("alias.child.test.", dns.TypeCNAME), Target: "www.good.test."}
	sigBad, sigGood := child.signZSK(t, toBad), child.signZSK(t, toGood)
	var calls atomic.Int32
	f.m.on("alias.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		n := calls.Add(1)
		resp := new(dns.Msg)
		if n == 1 {
			resp.Answer = []dns.RR{toBad, sigBad}
		} else {
			resp.Answer = []dns.RR{toGood, sigGood}
		}
		return resp
	})
	res := f.validate(t, "alias.child.test.")
	if res.Result != StatusBogus || len(res.CNAMEChains) != 1 || res.CNAMEChains[0].Target != "www.bad.test." {
		t.Fatalf("the authenticated first target must be followed: result=%s chains=%+v", res.Result, res.CNAMEChains)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("alias answer fetched %d times; traversal must not rediscover the target", n)
	}
}

func TestRA6X015_UnrelatedCNAMEIsNotFollowed(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	a := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	unrelated := &dns.CNAME{Hdr: rrHdr("elsewhere.child.test.", dns.TypeCNAME), Target: "attacker.invalid."}
	f.m.respond("www.child.test.", dns.TypeA, dns.RcodeSuccess, []dns.RR{a, child.signZSK(t, a)}, nil, []dns.RR{unrelated})
	res := f.validate(t, "www.child.test.")
	if res.Result != StatusSecure {
		t.Fatalf("secure answer expected, got %s errors=%v", res.Result, res.Errors)
	}
	if len(res.CNAMEChains) != 0 {
		t.Fatalf("an unrelated Additional CNAME must not be followed: %+v", res.CNAMEChains)
	}
	// Same-owner CNAME in Additional (not Answer) is not authenticated data either.
	sameOwner := &dns.CNAME{Hdr: rrHdr("www.child.test.", dns.TypeCNAME), Target: "attacker.invalid."}
	f.m.respond("www.child.test.", dns.TypeA, dns.RcodeSuccess, []dns.RR{a, child.signZSK(t, a)}, nil, []dns.RR{sameOwner})
	res = f.validate(t, "www.child.test.")
	if res.Result != StatusSecure || len(res.CNAMEChains) != 0 {
		t.Fatalf("Additional-section CNAME must not be followed: %s %+v", res.Result, res.CNAMEChains)
	}
}

func TestRA6X015_SameZoneAndCrossZoneAliases(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	other := f.addChild(t, "other.test.")
	serveAlias(t, f.m, child, "same.child.test.", "www.child.test.")
	serveA(t, f.m, child, "www.child.test.")
	serveAlias(t, f.m, child, "cross.child.test.", "www.other.test.")
	serveA(t, f.m, other, "www.other.test.")

	res := f.validate(t, "same.child.test.")
	if res.Result != StatusSecure || len(res.CNAMEChains) != 1 || res.CNAMEChains[0].Result != StatusSecure {
		t.Fatalf("same-zone alias: result=%s chains=%+v errors=%v", res.Result, res.CNAMEChains, res.Errors)
	}
	res = f.validate(t, "cross.child.test.")
	if res.Result != StatusSecure || len(res.CNAMEChains) != 1 || res.CNAMEChains[0].Target != "www.other.test." {
		t.Fatalf("cross-zone alias: result=%s chains=%+v errors=%v", res.Result, res.CNAMEChains, res.Errors)
	}
	leaf := res.Chain[len(res.Chain)-1]
	if leaf.RecordValidation == nil || leaf.RecordValidation.Target != "www.other.test." || leaf.RecordValidation.RecordType != "CNAME" {
		t.Fatalf("leaf record validation must carry the authenticated target: %+v", leaf.RecordValidation)
	}

	// Explicit CNAME query: complete on the authenticated RRset, no traversal.
	f.v.SetQueryType(dns.TypeCNAME)
	c := &dns.CNAME{Hdr: rrHdr("cross.child.test.", dns.TypeCNAME), Target: "www.other.test."}
	f.m.answer("cross.child.test.", dns.TypeCNAME, c, child.signZSK(t, c))
	res = f.validate(t, "cross.child.test.")
	if res.Result != StatusSecure || len(res.CNAMEChains) != 0 {
		t.Fatalf("explicit CNAME query must complete without traversal: %s %+v errors=%v", res.Result, res.CNAMEChains, res.Errors)
	}
}

func TestRA6X015_InsecureSourceStillBoundedByTarget(t *testing.T) {
	f := newChainFixture(t)
	insecure := f.addInsecureChild(t, "plain.test.")
	other := f.addChild(t, "other.test.")
	bad := f.addChild(t, "bad.test.")
	stranger := newTestZone(t, "bad.test.")
	f.m.answer("bad.test.", dns.TypeDNSKEY, append(bad.dnskeyRRset(), stranger.signKSK(t, bad.dnskeyRRset()...))...)
	serveA(t, f.m, other, "www.other.test.")
	serveA(t, f.m, bad, "www.bad.test.")
	// Unsigned CNAMEs in the insecure zone.
	f.m.answer("to-good.plain.test.", dns.TypeA, &dns.CNAME{Hdr: rrHdr("to-good.plain.test.", dns.TypeCNAME), Target: "www.other.test."})
	f.m.answer("to-bad.plain.test.", dns.TypeA, &dns.CNAME{Hdr: rrHdr("to-bad.plain.test.", dns.TypeCNAME), Target: "www.bad.test."})
	_ = insecure

	res := f.validate(t, "to-good.plain.test.")
	if res.Result != StatusInsecure || len(res.CNAMEChains) != 1 || res.CNAMEChains[0].Target != "www.other.test." {
		t.Fatalf("insecure alias to a secure target stays insecure (sticky ancestry): %s %+v", res.Result, res.CNAMEChains)
	}
	res = f.validate(t, "to-bad.plain.test.")
	if res.Result != StatusBogus {
		t.Fatalf("insecure alias to a bogus target is bogus, got %s", res.Result)
	}
	if !strings.Contains(strings.Join(res.Errors, "\n"), "www.bad.test.") {
		t.Fatalf("expected the bogus target to be named: %v", res.Errors)
	}
}

// The unauthenticated fallback has its own section/owner filter, and it is the
// one that matters most: below an insecure ancestor there is no signature to
// bound what gets followed, so discoverAliasTarget accepts only an
// Answer-section CNAME owned by the queried name (RA6X-015).
//
// TestRA6X015_UnrelatedCNAMEIsNotFollowed covers the same rule on the
// authenticated path, where the leaf RRset verification already excludes
// Additional; it is a secure zone, so it never reaches this code.
func TestRA6X015_InsecureAliasDiscoveryIgnoresOffOwnerAndAdditional(t *testing.T) {
	cases := []struct {
		name   string
		answer []dns.RR
		extra  []dns.RR
	}{
		{
			name:   "CNAME in Answer at another owner",
			answer: []dns.RR{&dns.CNAME{Hdr: rrHdr("elsewhere.plain.test.", dns.TypeCNAME), Target: "attacker.invalid."}},
		},
		{
			name:  "same-owner CNAME in Additional",
			extra: []dns.RR{&dns.CNAME{Hdr: rrHdr("decoy.plain.test.", dns.TypeCNAME), Target: "attacker.invalid."}},
		},
		{
			name:   "off-owner in Answer and same-owner in Additional",
			answer: []dns.RR{&dns.CNAME{Hdr: rrHdr("elsewhere.plain.test.", dns.TypeCNAME), Target: "attacker.invalid."}},
			extra:  []dns.RR{&dns.CNAME{Hdr: rrHdr("decoy.plain.test.", dns.TypeCNAME), Target: "other.invalid."}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newChainFixture(t)
			insecure := f.addInsecureChild(t, "plain.test.")
			_ = insecure
			f.m.respond("decoy.plain.test.", dns.TypeA, dns.RcodeSuccess, tc.answer, nil, tc.extra)

			res := f.validate(t, "decoy.plain.test.")
			if len(res.CNAMEChains) != 0 {
				t.Fatalf("no alias may be followed from an off-owner or Additional CNAME: %+v", res.CNAMEChains)
			}
			if res.Result == StatusSecure {
				t.Fatalf("an insecure zone's answer must not be secure, got %s", res.Result)
			}
		})
	}
}

// The control: the same insecure zone with a well-formed Answer-section CNAME
// owned by the queried name IS followed, so the test above is not passing
// merely because traversal is broken.
func TestRA6X015_InsecureAliasDiscoveryFollowsTheAnswerOwner(t *testing.T) {
	f := newChainFixture(t)
	insecure := f.addInsecureChild(t, "plain.test.")
	other := f.addChild(t, "other.test.")
	_ = insecure
	serveA(t, f.m, other, "www.other.test.")
	f.m.answer("real.plain.test.", dns.TypeA, &dns.CNAME{Hdr: rrHdr("real.plain.test.", dns.TypeCNAME), Target: "www.other.test."})

	res := f.validate(t, "real.plain.test.")
	if len(res.CNAMEChains) != 1 || res.CNAMEChains[0].Target != "www.other.test." {
		t.Fatalf("a well-formed Answer-section alias must still be followed: %+v", res.CNAMEChains)
	}
}
