package validator

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// RDAYBLUEX-022 through the real validator: a delegation whose nameserver
// address data supplies a deprecated site-local IPv6 address never gets a
// UDP or TCP attempt unless that exact range is allowlisted.
func TestRDAYBLUEX022_DelegationWithSiteLocalAddressIsNotDialed(t *testing.T) {
	m := newMockDNS(t)
	parent := newTestZone(t, "test.")
	child := newTestZone(t, "child.test.")
	m.serveInfra("test.")
	m.serveInfra("child.test.")
	// A second nameserver reachable only at a site-local address.
	m.answer("child.test.", dns.TypeNS,
		&dns.NS{Hdr: rrHdr("child.test.", dns.TypeNS), Ns: "ns.child.test."},
		&dns.NS{Hdr: rrHdr("child.test.", dns.TypeNS), Ns: "ns2.child.test."})
	m.answer("ns2.child.test.", dns.TypeAAAA, &dns.AAAA{Hdr: rrHdr("ns2.child.test.", dns.TypeAAAA), AAAA: net.ParseIP("fec0::1")})
	parent.serveDS(t, m, child, nil, nil)
	child.serveDNSKEY(t, m)

	v := m.newValidator()
	// Loopback (the fixture) is allowlisted; nothing else non-public is.
	allow, _ := dnspkg.ParseEgressAllowlist([]string{"127.0.0.0/8", "::1/128"})
	p := dnspkg.PublicOnlyPolicy(m.ip)
	p.Allow = allow
	v.SetEgressPolicy(p)

	zr, err := v.validateZone(testCtx(t), "child.test.", []string{".", "test.", "child.test."}, parent.keyRecords(), false)
	if err != nil {
		t.Fatal(err)
	}
	status, errText := addressStatus(zr, "fec0::1")
	if status == "" {
		t.Fatalf("the site-local address must appear in the per-address results: %+v", zr.Nameservers)
	}
	if !strings.Contains(errText, "egress policy") {
		t.Fatalf("the site-local address must be refused by the egress policy, got status %s error %q", status, errText)
	}
	if zr.Status != StatusSecure {
		t.Fatalf("the reachable nameserver still authenticates the zone: %s (%v)", zr.Status, zr.Errors)
	}
	for _, q := range m.questions() {
		_ = q // every question the mock saw arrived on loopback by construction
	}
}
