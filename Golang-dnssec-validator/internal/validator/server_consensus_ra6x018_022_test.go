package validator

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// RA6X-018 (Medium): per-server status must be an authentication verdict, not
// transport success; consensus compares complete key material and type-aware
// RDATA; one valid path suffices while every dissent is reported.

// dualServerFixture serves the child zone from two "servers" (127.0.0.1 and
// ::1) with a per-server override hook.
type dualServerFixture struct {
	m      *mockDNS
	parent *testZone
	child  *testZone
}

func newDualServerFixture(t *testing.T) *dualServerFixture {
	t.Helper()
	m := newMockDNS(t)
	if !m.enableDualStack(t) {
		t.Skip("IPv6 loopback unavailable; two-server fixture needs ::1")
	}
	f := &dualServerFixture{m: m, parent: newTestZone(t, "test."), child: newTestZone(t, "child.test.")}
	m.serveInfra("test.")
	m.serveInfra("child.test.")
	f.parent.serveDS(t, m, f.child, nil, nil)
	f.child.serveDNSKEY(t, m)
	return f
}

func (f *dualServerFixture) validate(t *testing.T) *ZoneResult {
	t.Helper()
	v := f.m.newValidator()
	zr, err := v.validateZone(testCtx(t), "child.test.", []string{".", "test.", "child.test."}, f.parent.keyRecords(), false)
	if err != nil {
		t.Fatalf("validateZone: %v", err)
	}
	return zr
}

func addressStatus(zr *ZoneResult, ip string) (ValidationStatus, string) {
	for _, ns := range zr.Nameservers {
		for _, a := range ns.Addresses {
			if a.IP == ip {
				return a.Status, a.Error
			}
		}
	}
	return "", "missing"
}

func TestRA6X018_PerServerVerdictsAreAuthentication(t *testing.T) {
	f := newDualServerFixture(t)
	// Both servers agree and verify: both secure, no disagreements.
	zr := f.validate(t)
	if zr.Status != StatusSecure {
		t.Fatalf("expected secure, got %s errors=%v", zr.Status, zr.Errors)
	}
	for _, ip := range []string{"127.0.0.1", "::1"} {
		if st, e := addressStatus(zr, ip); st != StatusSecure {
			t.Fatalf("%s: status=%s error=%q, want secure", ip, st, e)
		}
	}
	if len(zr.Disagreements) != 0 {
		t.Fatalf("no disagreement expected, got %+v", zr.Disagreements)
	}

	// The v6 server serves identical keys with a missing signature: it must be
	// flagged bogus and recorded, while the zone stays secure via v4.
	f.m.onFamily("v6", "child.test.", dns.TypeDNSKEY, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = f.child.dnskeyRRset()
		return resp
	})
	zr = f.validate(t)
	if zr.Status != StatusSecure {
		t.Fatalf("one valid path must keep the zone secure, got %s", zr.Status)
	}
	if st, e := addressStatus(zr, "::1"); st != StatusBogus || !strings.Contains(e, "RRSIG") {
		t.Fatalf("unsigned server must be bogus with a signature reason: %s %q", st, e)
	}
	if st, _ := addressStatus(zr, "127.0.0.1"); st != StatusSecure {
		t.Fatalf("signing server must be secure, got %s", st)
	}
	if len(zr.Disagreements) != 1 || zr.Disagreements[0].IP != "::1" {
		t.Fatalf("expected one disagreement for ::1, got %+v", zr.Disagreements)
	}

	// Same-tag different key: material comparison catches what a tag compare
	// cannot. The v6 server serves a stranger's keys signed by the stranger.
	stranger := newTestZone(t, "child.test.")
	f.m.onFamily("v6", "child.test.", dns.TypeDNSKEY, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = append(stranger.dnskeyRRset(), stranger.signKSK(t, stranger.dnskeyRRset()...))
		return resp
	})
	zr = f.validate(t)
	if zr.Status != StatusSecure {
		t.Fatalf("expected secure via v4, got %s", zr.Status)
	}
	if st, _ := addressStatus(zr, "::1"); st != StatusBogus {
		t.Fatalf("server with different key material must be bogus, got %s", st)
	}
	if len(zr.Disagreements) != 1 || !strings.Contains(zr.Disagreements[0].Issue, "differs") {
		t.Fatalf("expected a key-material disagreement, got %+v", zr.Disagreements)
	}

	// Empty DNSKEY response on one server is a disagreement, not skipped.
	f.m.onFamily("v6", "child.test.", dns.TypeDNSKEY, func(req *dns.Msg) *dns.Msg { return new(dns.Msg) })
	zr = f.validate(t)
	if zr.Status != StatusSecure {
		t.Fatalf("expected secure via v4, got %s", zr.Status)
	}
	if st, e := addressStatus(zr, "::1"); st != StatusBogus || !strings.Contains(e, "no DNSKEY") {
		t.Fatalf("empty DNSKEY server must be bogus: %s %q", st, e)
	}

	// The FIRST server broken and the second fine: the valid path is found.
	f.m.clearFamilyOverrides()
	f.m.onFamily("v4", "child.test.", dns.TypeDNSKEY, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = f.child.dnskeyRRset() // unsigned
		return resp
	})
	zr = f.validate(t)
	if zr.Status != StatusSecure {
		t.Fatalf("a valid second server must establish the chain, got %s errors=%v", zr.Status, zr.Errors)
	}
	if st, _ := addressStatus(zr, "127.0.0.1"); st != StatusBogus {
		t.Fatalf("first (broken) server must be bogus, got %s", st)
	}
	if st, _ := addressStatus(zr, "::1"); st != StatusSecure {
		t.Fatalf("second server must be secure, got %s", st)
	}

	// Nonresponder: indeterminate, not secure.
	f.m.clearFamilyOverrides()
	f.m.drop("child.test.", dns.TypeDNSKEY)
	v := f.m.newValidatorWithTimeout(300 * time.Millisecond)
	zr, err := v.validateZone(testCtx(t), "child.test.", []string{".", "test.", "child.test."}, f.parent.keyRecords(), false)
	if err != nil {
		t.Fatalf("validateZone: %v", err)
	}
	if zr.Status != StatusIndeterminate {
		t.Fatalf("no responder must be indeterminate, got %s", zr.Status)
	}
	for _, ip := range []string{"127.0.0.1", "::1"} {
		if st, _ := addressStatus(zr, ip); st != StatusIndeterminate {
			t.Fatalf("%s nonresponder status = %s", ip, st)
		}
	}
}

func TestRA6X018_LeafConsensusAndFingerprint(t *testing.T) {
	f := newDualServerFixture(t)
	v := f.m.newValidator()
	a := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	sig := f.child.signZSK(t, a)
	f.m.answer("www.child.test.", dns.TypeA, a, sig)

	// Identical data, signature missing on the v6 server: flagged.
	f.m.onFamily("v6", "www.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{a}
		return resp
	})
	rv := v.verifyActualRecord(testCtx(t), "www.child.test.", "child.test.", f.child.keyRecords())
	if !rv.RRSIGVerified {
		t.Fatalf("leaf must verify via the signing server: %+v", rv)
	}
	if len(rv.ServerDisagreements) != 1 || !strings.Contains(rv.ServerDisagreements[0], "signature does not verify") {
		t.Fatalf("unsigned second server must be flagged: %+v", rv.ServerDisagreements)
	}

	// First server broken (expired), second fine: the valid answer is chosen.
	expired := f.child.signZSK(t, a)
	expired.Expiration = uint32(1)
	expired.Inception = uint32(0)
	if err := expired.Sign(f.child.zskSigner, []dns.RR{a}); err != nil {
		t.Fatal(err)
	}
	f.m.clearFamilyOverrides()
	f.m.onFamily("v4", "www.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{a, expired}
		return resp
	})
	rv = v.verifyActualRecord(testCtx(t), "www.child.test.", "child.test.", f.child.keyRecords())
	if !rv.RRSIGVerified {
		t.Fatalf("valid answer on the second server must be used: %+v", rv)
	}
	if len(rv.ServerDisagreements) != 1 {
		t.Fatalf("broken first server must be flagged: %+v", rv.ServerDisagreements)
	}

	// Fingerprint semantics: TTL-only differences and case-insensitive
	// domain-name RDATA are equal; TXT case, duplicates and real differences
	// are handled type-aware.
	fp := func(rrs ...dns.RR) string {
		msg := new(dns.Msg)
		msg.SetQuestion("x.child.test.", dns.TypeTXT)
		msg.Answer = rrs
		raw, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}
		qr := dnsQueryResultRaw(raw)
		return v.leafFingerprint(&qr)
	}
	v.SetQueryType(dns.TypeMX)
	mx1 := &dns.MX{Hdr: rrHdr("x.child.test.", dns.TypeMX), Preference: 10, Mx: "Mail.Child.Test."}
	mx2 := &dns.MX{Hdr: rrHdr("X.child.test.", dns.TypeMX), Preference: 10, Mx: "mail.child.test."}
	mx2.Hdr.Ttl = 5
	if fp(mx1) != fp(mx2) {
		t.Fatal("TTL-only and name-case differences must fingerprint equal")
	}
	if fp(mx1) != fp(mx1, mx1) {
		t.Fatal("duplicate records must not change the fingerprint")
	}
	v.SetQueryType(dns.TypeTXT)
	txt1 := &dns.TXT{Hdr: rrHdr("x.child.test.", dns.TypeTXT), Txt: []string{"v=spf1 -all"}}
	txt2 := &dns.TXT{Hdr: rrHdr("x.child.test.", dns.TypeTXT), Txt: []string{"V=SPF1 -ALL"}}
	if fp(txt1) == fp(txt2) {
		t.Fatal("TXT case differences are real differences")
	}
}

// RA6X-022 (Medium): exactly one terminal event for the top-level request,
// nested failures carried as CNAME results, zone authentication cached apart
// from per-name answer validation, and the leaf zone re-sent with its record
// validation.
func TestRA6X022_OneTerminalEventAndPerNameResults(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	bad := f.addChild(t, "bad.test.")
	stranger := newTestZone(t, "bad.test.")
	f.m.answer("bad.test.", dns.TypeDNSKEY, append(bad.dnskeyRRset(), stranger.signKSK(t, bad.dnskeyRRset()...))...)
	serveAlias(t, f.m, child, "alias.child.test.", "www.bad.test.")
	serveA(t, f.m, bad, "www.bad.test.")

	var events []SSEEvent
	f.v.SetEventCallback(func(e SSEEvent) { events = append(events, e) })
	res := f.validate(t, "alias.child.test.")
	if res.Result != StatusBogus {
		t.Fatalf("expected bogus, got %s", res.Result)
	}
	completes := 0
	var last CompleteEvent
	leafReemitted := false
	for _, e := range events {
		switch e.Type {
		case "complete":
			completes++
			last = e.Data.(CompleteEvent)
		case "zone":
			ze := e.Data.(ZoneEvent)
			if ze.Zone == "child.test." && ze.ZoneResult != nil && ze.ZoneResult.RecordValidation != nil && ze.Depth == 0 {
				leafReemitted = true
			}
		}
	}
	if completes != 1 {
		t.Fatalf("expected exactly one complete event, got %d", completes)
	}
	if len(last.Chain) == 0 || last.Chain[len(last.Chain)-1].Zone != "child.test." {
		t.Fatalf("complete event must carry the original chain: %+v", last.Chain)
	}
	if len(last.CNAMEChains) != 1 || last.CNAMEChains[0].Result != StatusBogus {
		t.Fatalf("nested failure must be carried as a CNAME result: %+v", last.CNAMEChains)
	}
	if !leafReemitted {
		t.Fatal("leaf zone must be re-emitted with its record validation")
	}
	leaf := last.Chain[len(last.Chain)-1]
	if leaf.RecordValidation == nil || leaf.RecordValidation.Name != "alias.child.test." {
		t.Fatalf("leaf record validation must be identified by name: %+v", leaf.RecordValidation)
	}
}

func TestRA6X022_SameZoneAliasesKeepSeparateRecordValidation(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	// good.child.test. → www.child.test. (secure); the target has a valid A.
	serveAlias(t, f.m, child, "good.child.test.", "www.child.test.")
	serveA(t, f.m, child, "www.child.test.")

	cache := f.seedCache()
	res, err := f.v.validateWithCache(testCtx(t), "good.child.test.", 0, make(map[string]bool), cache)
	if err != nil {
		t.Fatal(err)
	}
	if res.Result != StatusSecure {
		t.Fatalf("expected secure, got %s errors=%v", res.Result, res.Errors)
	}
	// The cached zone object carries zone authentication only.
	if cached := cache["child.test."]; cached == nil || cached.RecordValidation != nil {
		t.Fatalf("cache must not hold per-name record validation: %+v", cached)
	}
	// The source name's chain leaf holds ITS validation (the CNAME), and the
	// alias hop's chain leaf holds the target's (the A).
	src := res.Chain[len(res.Chain)-1].RecordValidation
	if src == nil || src.RecordType != "CNAME" || src.Name != "good.child.test." {
		t.Fatalf("source leaf validation = %+v", src)
	}
	if len(res.CNAMEChains) != 1 {
		t.Fatalf("expected one alias hop, got %+v", res.CNAMEChains)
	}
	tgt := res.CNAMEChains[0].Chain[len(res.CNAMEChains[0].Chain)-1].RecordValidation
	if tgt == nil || tgt.RecordType != "A" || tgt.Name != "www.child.test." {
		t.Fatalf("target leaf validation = %+v", tgt)
	}
}
