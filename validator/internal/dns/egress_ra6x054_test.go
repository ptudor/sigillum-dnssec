package dns

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestEgressPolicy_Permit(t *testing.T) {
	p := PublicOnlyPolicy("127.0.0.1", "resolver.internal")
	allowed := []string{"1.1.1.1", "2620:fe::fe", "[2001:4860:4860::8888]:53", "8.8.8.8:53",
		"127.0.0.1", "127.0.0.1:5353", "resolver.internal"} // the last three are trusted
	for _, a := range allowed {
		if err := p.Permit(a); err != nil {
			t.Errorf("%s must be permitted: %v", a, err)
		}
	}
	refused := []string{"127.0.0.2", "::1", "[::1]:53", "10.1.2.3", "172.16.5.5", "192.168.1.1", "100.64.0.9",
		"169.254.1.1", "fe80::1", "fd00::1", "224.0.0.251", "ff02::1", "0.0.0.0", "::", "240.0.0.1",
		"::ffff:10.0.0.1", "::ffff:127.0.0.9", "64:ff9b::a00:1", "2001:db8::1", "ns.example.com"}
	for _, a := range refused {
		if err := p.Permit(a); err == nil {
			t.Errorf("%s must be refused by the public-only policy", a)
		}
	}
	// Allowlist and blanket allowance.
	allow, err := ParseEgressAllowlist([]string{"10.0.0.0/8", " ::1/128 "})
	if err != nil {
		t.Fatal(err)
	}
	p.Allow = allow
	for _, a := range []string{"10.1.2.3", "::1", "::ffff:10.9.9.9"} {
		if err := p.Permit(a); err != nil {
			t.Errorf("allowlisted %s must be permitted: %v", a, err)
		}
	}
	if err := p.Permit("192.168.1.1"); err == nil {
		t.Error("an address outside the allowlist stays refused")
	}
	p.AllowPrivate = true
	if err := p.Permit("192.168.1.1"); err != nil {
		t.Error("allow_private_destinations permits everything")
	}
	if _, err := ParseEgressAllowlist([]string{"not-a-cidr"}); err == nil {
		t.Error("invalid CIDRs must be rejected")
	}
	var nilPolicy *EgressPolicy
	if err := nilPolicy.Permit("127.0.0.1"); err != nil {
		t.Error("a nil policy permits everything")
	}
}

// The policy is enforced at the dial boundary for every transport: a
// hermetic loopback authoritative server is refused under the public-only
// policy (both the UDP attempt and the TCP retry would go through the same
// check), reached once allowlisted, and the trusted recursive resolver is
// always reachable.
func TestQuerier_EgressEnforcedAtDial(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	var hits atomic.Int64
	srv := &dns.Server{PacketConn: pc, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		hits.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("198.51.100.1")})
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	<-started
	defer srv.Shutdown()
	_, port, _ := net.SplitHostPort(pc.LocalAddr().String())

	q := NewQuerier(2 * time.Second)
	q.port = port
	ctx := context.Background()

	// Query records transport-level failures in the result rather than
	// returning a Go error; the refusal must be there and nothing must have
	// been sent.
	q.SetEgressPolicy(PublicOnlyPolicy())
	res, err := q.Query(ctx, "127.0.0.1", "www.example.com.", dns.TypeA)
	if err != nil || !strings.Contains(res.Error, "egress policy") {
		t.Fatalf("a loopback authoritative destination must be refused by the public-only policy, got err=%v result=%+v", err, res)
	}
	res, err = q.QueryWithRecursion(ctx, "::1", "www.example.com.", dns.TypeA, true)
	if err != nil || !strings.Contains(res.Error, "egress policy") {
		t.Fatalf("an IPv6 loopback destination must be refused too, got err=%v result=%+v", err, res)
	}
	if got := hits.Load(); got != 0 {
		t.Fatalf("no query may reach a refused destination, server saw %d", got)
	}

	allow, _ := ParseEgressAllowlist([]string{"127.0.0.0/8"})
	p := PublicOnlyPolicy()
	p.Allow = allow
	q.SetEgressPolicy(p)
	res, err = q.Query(ctx, "127.0.0.1", "www.example.com.", dns.TypeA)
	if err != nil || res.RCode != dns.RcodeSuccess {
		t.Fatalf("an allowlisted destination must be queried: %v (%+v)", err, res)
	}

	q.SetEgressPolicy(PublicOnlyPolicy("127.0.0.1"))
	if res, err := q.Query(ctx, "127.0.0.1", "www.example.com.", dns.TypeA); err != nil || res.Error != "" {
		t.Fatalf("the trusted resolver must always be reachable: %v %+v", err, res)
	}
	if res, err := q.Query(ctx, "127.0.0.2", "www.example.com.", dns.TypeA); err != nil || !strings.Contains(res.Error, "egress policy") {
		t.Fatalf("another loopback address is not the trusted resolver, got %v %+v", err, res)
	}
	if got := hits.Load(); got != 2 {
		t.Fatalf("exactly the two permitted queries may reach the server, saw %d", got)
	}
}
