package dns

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// infraMock is a loopback recursive-resolver stand-in serving UDP and TCP.
type infraMock struct {
	t        *testing.T
	udp, tcp *dns.Server
	host     string
	port     string

	mu       sync.Mutex
	handlers map[string]func(req *dns.Msg) *dns.Msg // key: name/qtype
	truncate map[string]bool
	drop     map[string]bool
}

func key(name string, qtype uint16) string {
	return dns.CanonicalName(name) + "/" + dns.TypeToString[qtype]
}

func newInfraMock(t *testing.T) *infraMock {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, _ := net.SplitHostPort(pc.LocalAddr().String())
	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	m := &infraMock{t: t, host: host, port: port, handlers: map[string]func(*dns.Msg) *dns.Msg{}, truncate: map[string]bool{}, drop: map[string]bool{}}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		q := req.Question[0]
		k := key(q.Name, q.Qtype)
		m.mu.Lock()
		h, trunc, drop := m.handlers[k], m.truncate[k], m.drop[k]
		m.mu.Unlock()
		if drop {
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		if trunc && w.RemoteAddr().Network() == "udp" {
			resp.Truncated = true
			_ = w.WriteMsg(resp)
			return
		}
		if h != nil {
			r := h(req)
			rcode := r.Rcode
			r.SetReply(req)
			r.Rcode = rcode
			resp = r
		}
		_ = w.WriteMsg(resp)
	})
	started := make(chan struct{}, 2)
	m.udp = &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { started <- struct{}{} }}
	m.tcp = &dns.Server{Listener: ln, Handler: mux, NotifyStartedFunc: func() { started <- struct{}{} }}
	go func() { _ = m.udp.ActivateAndServe() }()
	go func() { _ = m.tcp.ActivateAndServe() }()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("mock did not start")
		}
	}
	t.Cleanup(func() { _ = m.udp.Shutdown(); _ = m.tcp.Shutdown() })
	return m
}

func (m *infraMock) on(name string, qtype uint16, rcode int, answer ...dns.RR) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[key(name, qtype)] = func(req *dns.Msg) *dns.Msg {
		r := new(dns.Msg)
		r.Rcode = rcode
		r.Answer = answer
		return r
	}
}

func (m *infraMock) setTruncate(name string, qtype uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.truncate[key(name, qtype)] = true
}

func (m *infraMock) setDrop(name string, qtype uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drop[key(name, qtype)] = true
}

func (m *infraMock) resolver() *Resolver {
	r := NewResolver(500*time.Millisecond, m.host)
	r.SetDefaultPort(m.port)
	return r
}

func hdr(name string, t uint16) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: t, Class: dns.ClassINET, Ttl: 300}
}

// A truncated UDP answer must be retried over TCP and the complete answer used.
func TestRA6X019_TruncatedUDPRetriedOverTCP(t *testing.T) {
	m := newInfraMock(t)
	nsRRs := []dns.RR{
		&dns.NS{Hdr: hdr("example.", dns.TypeNS), Ns: "a.ns.example."},
		&dns.NS{Hdr: hdr("example.", dns.TypeNS), Ns: "b.ns.example."},
		&dns.NS{Hdr: hdr("example.", dns.TypeNS), Ns: "c.ns.example."},
	}
	m.on("example.", dns.TypeNS, dns.RcodeSuccess, nsRRs...)
	m.setTruncate("example.", dns.TypeNS)
	m.on("a.ns.example.", dns.TypeA, dns.RcodeSuccess,
		&dns.A{Hdr: hdr("a.ns.example.", dns.TypeA), A: net.ParseIP("192.0.2.1")},
		&dns.A{Hdr: hdr("a.ns.example.", dns.TypeA), A: net.ParseIP("192.0.2.2")})
	m.setTruncate("a.ns.example.", dns.TypeA)

	r := m.resolver()
	ns, err := r.ResolveNS(context.Background(), "example.")
	if err != nil || len(ns) != 3 {
		t.Fatalf("ResolveNS over TC/TCP = %+v, %v; want all 3 NS", ns, err)
	}
	if ok, err := r.CheckZoneCut(context.Background(), "example."); err != nil || !ok {
		t.Fatalf("CheckZoneCut over TC/TCP = %v, %v", ok, err)
	}
	addrs, err := r.ResolveAddresses(context.Background(), "a.ns.example.")
	if err != nil || len(addrs) != 2 {
		t.Fatalf("ResolveAddresses over TC/TCP = %v, %v; want 2 addresses", addrs, err)
	}
}

// NS records must be owned by the requested name; aliases and unrelated owners
// are not this zone's nameservers.
func TestRA6X019_NSOwnerBinding(t *testing.T) {
	m := newInfraMock(t)
	m.on("example.", dns.TypeNS, dns.RcodeSuccess,
		&dns.NS{Hdr: hdr("other.example.", dns.TypeNS), Ns: "ns.other.example."})
	m.on("alias.example.", dns.TypeNS, dns.RcodeSuccess,
		&dns.CNAME{Hdr: hdr("alias.example.", dns.TypeCNAME), Target: "real.example."},
		&dns.NS{Hdr: hdr("real.example.", dns.TypeNS), Ns: "ns.real.example."})
	m.on("mixed.example.", dns.TypeNS, dns.RcodeSuccess,
		&dns.NS{Hdr: hdr("mixed.example.", dns.TypeNS), Ns: "ns1.mixed.example."},
		&dns.NS{Hdr: hdr("decoy.example.", dns.TypeNS), Ns: "ns.decoy.example."})
	r := m.resolver()

	if ns, err := r.ResolveNS(context.Background(), "example."); err != nil || len(ns) != 0 {
		t.Fatalf("unrelated-owner NS must be ignored: %+v, %v", ns, err)
	}
	if ok, _ := r.CheckZoneCut(context.Background(), "example."); ok {
		t.Fatal("unrelated-owner NS must not make example. a zone cut")
	}
	if ns, err := r.ResolveNS(context.Background(), "alias.example."); err != nil || len(ns) != 0 {
		t.Fatalf("NS reached through an alias must not be this name's NS: %+v, %v", ns, err)
	}
	if ok, _ := r.CheckZoneCut(context.Background(), "alias.example."); ok {
		t.Fatal("an aliased name is not a zone cut")
	}
	ns, err := r.ResolveNS(context.Background(), "mixed.example.")
	if err != nil || len(ns) != 1 || ns[0].Name != "ns1.mixed.example." || ns[0].Owner != "mixed.example." {
		t.Fatalf("only the requested owner's NS must be kept: %+v, %v", ns, err)
	}
}

// Failure RCODEs and dropped replies are errors, not silently empty results;
// a partial address lookup keeps the working family and reports the other.
func TestRA6X019_ErrorsAndPartialFamilies(t *testing.T) {
	m := newInfraMock(t)
	m.on("broken.example.", dns.TypeNS, dns.RcodeRefused)
	m.on("gone.example.", dns.TypeNS, dns.RcodeNameError)
	m.on("ns.example.", dns.TypeA, dns.RcodeServerFailure)
	m.on("ns.example.", dns.TypeAAAA, dns.RcodeSuccess, &dns.AAAA{Hdr: hdr("ns.example.", dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::1")})
	m.on("dead.example.", dns.TypeA, dns.RcodeServerFailure)
	m.on("dead.example.", dns.TypeAAAA, dns.RcodeRefused)
	m.on("cname.example.", dns.TypeA, dns.RcodeSuccess,
		&dns.CNAME{Hdr: hdr("cname.example.", dns.TypeCNAME), Target: "host.example."},
		&dns.A{Hdr: hdr("host.example.", dns.TypeA), A: net.ParseIP("192.0.2.9")},
		&dns.A{Hdr: hdr("unrelated.example.", dns.TypeA), A: net.ParseIP("192.0.2.10")})
	m.setDrop("slow.example.", dns.TypeA)
	m.on("slow.example.", dns.TypeAAAA, dns.RcodeSuccess, &dns.AAAA{Hdr: hdr("slow.example.", dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::2")})
	m.on("zone.example.", dns.TypeNS, dns.RcodeSuccess, &dns.NS{Hdr: hdr("zone.example.", dns.TypeNS), Ns: "ns.example."})
	r := m.resolver()

	if _, err := r.ResolveNS(context.Background(), "broken.example."); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("REFUSED must be an error, got %v", err)
	}
	if ns, err := r.ResolveNS(context.Background(), "gone.example."); err != nil || len(ns) != 0 {
		t.Fatalf("NXDOMAIN yields no nameservers without error: %+v, %v", ns, err)
	}
	addrs, problems, err := r.ResolveAddressesDetailed(context.Background(), "ns.example.")
	if err != nil || len(addrs) != 1 || len(problems) != 1 || !strings.Contains(problems[0], "SERVFAIL") {
		t.Fatalf("partial lookup = %v %v %v; want the AAAA and a reported A failure", addrs, problems, err)
	}
	if _, err := r.ResolveAddresses(context.Background(), "dead.example."); err == nil {
		t.Fatal("both families failing must be an error")
	}
	addrs, err = r.ResolveAddresses(context.Background(), "cname.example.")
	if err != nil || len(addrs) != 1 || !addrs[0].Equal(net.ParseIP("192.0.2.9")) {
		t.Fatalf("aliased host must yield the target's addresses only: %v, %v", addrs, err)
	}
	addrs, problems, err = r.ResolveAddressesDetailed(context.Background(), "slow.example.")
	if err != nil || len(addrs) != 1 || len(problems) != 1 {
		t.Fatalf("timed-out A with working AAAA = %v %v %v", addrs, problems, err)
	}
	ns, err := r.ResolveNSWithAddresses(context.Background(), "zone.example.")
	if err != nil || len(ns) != 1 || len(ns[0].Addresses) != 1 || len(ns[0].LookupErrors) != 1 {
		t.Fatalf("ResolveNSWithAddresses must carry the family problem: %+v, %v", ns, err)
	}
}
