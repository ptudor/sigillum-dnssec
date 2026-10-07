package validator

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// RM51X-005: a zone that could not be authenticated must not hand keys to
// its children. Before the fix the walk carried either the grandparent's keys
// (parent indeterminate without a DNSKEY) or the parent's unauthenticated
// served keys (parent indeterminate after a DS failure) into the child's DS
// verification, so a transient availability failure read bogus, or a child
// below an unauthenticated parent read secure with a chain link.

func rm51x005Zone(t *testing.T, res *ValidationResult, zone string) *ZoneResult {
	t.Helper()
	for i := range res.Chain {
		if res.Chain[i].Zone == zone {
			return &res.Chain[i]
		}
	}
	t.Fatalf("zone %s missing from chain %v", zone, res.Chain)
	return nil
}

func rm51x005AssertUnverified(t *testing.T, zr *ZoneResult, ancestor string) {
	t.Helper()
	if zr.Status != StatusIndeterminate {
		t.Fatalf("%s: status %s, want indeterminate below unauthenticated ancestor", zr.Zone, zr.Status)
	}
	if zr.ChainLink != nil {
		t.Fatalf("%s: chain link recorded below an unauthenticated ancestor", zr.Zone)
	}
	if zr.DSValidation != nil {
		t.Fatalf("%s: DS verification ran below an unauthenticated ancestor: %+v", zr.Zone, zr.DSValidation)
	}
	found := false
	for _, e := range zr.Errors {
		if strings.Contains(e, "DS RRSIG verification failed") {
			t.Fatalf("%s: availability failure reported as a signature failure: %s", zr.Zone, e)
		}
		if strings.Contains(e, ancestor) && strings.Contains(e, "could not be authenticated") {
			found = true
		}
	}
	if !found {
		t.Fatalf("%s: no error naming the unauthenticated ancestor %s, got %v", zr.Zone, ancestor, zr.Errors)
	}
}

// The parent's DNSKEY query times out on every server; the child's DS at the
// parent is served normally. The child must not be verified under the
// grandparent's keys and the verdict must stay indeterminate.
func TestRM51X005_ParentWithoutKeysDoesNotMakeChildBogus(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	a := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	f.m.answer("www.child.test.", dns.TypeA, a, child.signZSK(t, a))
	f.m.drop("test.", dns.TypeDNSKEY)
	cache := f.seedCache()
	delete(cache, "test.")

	res, err := f.v.validateWithCache(testCtx(t), "www.child.test.", 0, map[string]bool{}, cache)
	if err != nil && res == nil {
		t.Fatal(err)
	}
	if res.Result != StatusIndeterminate {
		t.Fatalf("verdict %s, want indeterminate (errors %v)", res.Result, res.Errors)
	}
	if p := rm51x005Zone(t, res, "test."); p.Status != StatusIndeterminate {
		t.Fatalf("parent status %s, want indeterminate", p.Status)
	}
	rm51x005AssertUnverified(t, rm51x005Zone(t, res, "child.test."), "test.")
}

// The parent's DNSKEY RRset is served but its own DS query fails, so the
// parent is indeterminate with unauthenticated keys attached for diagnostics.
// Those keys must not authenticate the child's DS.
func TestRM51X005_UnauthenticatedParentKeysDoNotSecureChild(t *testing.T) {
	f := newChainFixture(t)
	f.parent.serveDNSKEY(t, f.m)
	child := f.addChild(t, "child.test.")
	a := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	f.m.answer("www.child.test.", dns.TypeA, a, child.signZSK(t, a))
	f.m.drop("test.", dns.TypeDS)
	cache := f.seedCache()
	delete(cache, "test.")

	res, err := f.v.validateWithCache(testCtx(t), "www.child.test.", 0, map[string]bool{}, cache)
	if err != nil && res == nil {
		t.Fatal(err)
	}
	if res.Result != StatusIndeterminate {
		t.Fatalf("verdict %s, want indeterminate (errors %v)", res.Result, res.Errors)
	}
	p := rm51x005Zone(t, res, "test.")
	if p.Status != StatusIndeterminate {
		t.Fatalf("parent status %s, want indeterminate", p.Status)
	}
	if len(p.DNSKEY) == 0 {
		t.Fatalf("parent's served DNSKEY set should remain as diagnostics")
	}
	rm51x005AssertUnverified(t, rm51x005Zone(t, res, "child.test."), "test.")
}

// The cached-zone path must apply the same rule: an indeterminate ancestor
// reused from the cache (as happens on an alias hop) carries no keys down.
func TestRM51X005_CachedIndeterminateAncestorIsNotATrustSource(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	a := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	f.m.answer("www.child.test.", dns.TypeA, a, child.signZSK(t, a))
	cache := f.seedCache()
	parent := NewZoneResult("test.")
	parent.Status = StatusIndeterminate
	parent.DNSKEY = f.parent.keyRecords() // served, never authenticated
	parent.AddError("failed to query DS from parent")
	cache["test."] = parent

	res, err := f.v.validateWithCache(testCtx(t), "www.child.test.", 0, map[string]bool{}, cache)
	if err != nil && res == nil {
		t.Fatal(err)
	}
	if res.Result != StatusIndeterminate {
		t.Fatalf("verdict %s, want indeterminate", res.Result)
	}
	rm51x005AssertUnverified(t, rm51x005Zone(t, res, "child.test."), "test.")
}

// The inverse guard: an unsigned child below an indeterminate parent must
// not be laundered into insecure (the fail-closed property the previous
// nextParentDNSKEY comment protected) — it is indeterminate too.
func TestRM51X005_UnsignedChildOfIndeterminateParentIsNotInsecure(t *testing.T) {
	f := newChainFixture(t)
	f.addInsecureChild(t, "plain.test.")
	f.m.drop("test.", dns.TypeDNSKEY)
	cache := f.seedCache()
	delete(cache, "test.")

	res, err := f.v.validateWithCache(testCtx(t), "plain.test.", 0, map[string]bool{}, cache)
	if err != nil && res == nil {
		t.Fatal(err)
	}
	if res.Result != StatusIndeterminate {
		t.Fatalf("verdict %s, want indeterminate", res.Result)
	}
	c := rm51x005Zone(t, res, "plain.test.")
	if c.Status == StatusInsecure || c.Status == StatusSecure {
		t.Fatalf("unsigned child below an unauthenticated parent reads %s", c.Status)
	}
	rm51x005AssertUnverified(t, c, "test.")
}

// Control: the same child under a secure parent still validates, so the new
// gate does not fire when the chain is intact.
func TestRM51X005_SecureParentStillSecuresChild(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	a := &dns.A{Hdr: rrHdr("www.child.test.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	f.m.answer("www.child.test.", dns.TypeA, a, child.signZSK(t, a))
	res := f.validate(t, "www.child.test.")
	if res.Result != StatusSecure {
		t.Fatalf("verdict %s, want secure (errors %v)", res.Result, res.Errors)
	}
	if zr := rm51x005Zone(t, res, "child.test."); zr.ChainLink == nil || len(nextParentDNSKEY(zr)) == 0 {
		t.Fatalf("secure child should carry a chain link and authenticated keys")
	}
	var _ []dnspkg.DNSKEYRecord = nextParentDNSKEY(rm51x005Zone(t, res, "test."))
}
