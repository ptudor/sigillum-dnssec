package validator

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// Through the real validation path: with the public-only policy the
// fixture's loopback authoritative servers are refused and the zone cannot be
// evaluated (reported, never dialled); with the allowlist they are reached.
func TestValidate_PublicOnlyEgressRefusesFixtureAddresses(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "egress.test.")
	serveA(t, f.m, child, "www.egress.test.")
	// The fixture's recursive resolver lives on 127.0.0.1 and is trusted by
	// the policy; the authoritative servers are dialled on ::1 so the policy
	// can tell the two apart.
	if !f.m.enableDualStack(t) {
		t.Skip("IPv6 loopback unavailable")
	}
	// Advertise the parent's and the child's nameservers on ::1 only. The root
	// and parent zones are seeded into the validated cache, so the DS query at
	// the parent and every child query are the authoritative dials.
	for _, ns := range []string{"ns.test.", "ns." + child.name} {
		f.m.answer(ns, dns.TypeA)
		f.m.answer(ns, dns.TypeAAAA, &dns.AAAA{Hdr: rrHdr(ns, dns.TypeAAAA), AAAA: net.ParseIP("::1")})
	}

	policy := dnspkg.PublicOnlyPolicy(f.m.ip) // the recursive resolver stays trusted
	f.v.SetEgressPolicy(policy)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	run := func() *ValidationResult {
		res, _ := f.v.validateWithCache(ctx, "www.egress.test.", 0, make(map[string]bool), f.seedCache())
		return res
	}
	res := run()
	if res == nil {
		t.Fatal("a result is expected even when every authoritative dial is refused")
	}
	if res.Result == StatusSecure {
		t.Fatal("no authoritative server may be dialled on loopback under the public-only policy")
	}
	// Authoritative queries (DNSKEY/DS) never reach the loopback servers; the
	// trusted recursive resolver (the same mock) may still be asked NS/A.
	if n := authoritativeQueriesSeen(f.m); n != 0 {
		t.Fatalf("no authoritative dial may reach a refused destination, saw %d", n)
	}

	allow, _ := dnspkg.ParseEgressAllowlist([]string{"127.0.0.0/8", "::1/128"})
	policy.Allow = allow
	f.v.SetEgressPolicy(policy)
	res = run()
	if res == nil || res.Result != StatusSecure {
		t.Fatalf("with the allowlist the same validation must succeed, got %+v", res)
	}
	if n := authoritativeQueriesSeen(f.m); n == 0 {
		t.Fatal("allowlisted authoritative servers must be queried")
	}
}

// authoritativeQueriesSeen counts the questions the mock received without
// recursion desired — the authoritative dials, as opposed to lookups sent to
// it in its role as the trusted recursive resolver.
func authoritativeQueriesSeen(m *mockDNS) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for i := range m.seen {
		if i < len(m.seenRecursive) && !m.seenRecursive[i] {
			n++
		}
	}
	return n
}
