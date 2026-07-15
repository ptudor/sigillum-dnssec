package dns

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// recordingResolver is a minimal local DNS server standing in for the configured
// recursive resolver. It records the CD bit of every query it receives and, like
// a validating resolver faced with a DNSSEC-broken zone, answers SERVFAIL unless
// the client asked it to stop checking.
type recordingResolver struct {
	t    *testing.T
	srv  *dns.Server
	addr string

	mu     sync.Mutex
	cdSeen []bool
}

func newRecordingResolver(t *testing.T) *recordingResolver {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	r := &recordingResolver{t: t, addr: pc.LocalAddr().String()}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		r.mu.Lock()
		r.cdSeen = append(r.cdSeen, req.CheckingDisabled)
		r.mu.Unlock()

		m := new(dns.Msg)
		m.SetReply(req)

		// Emulate a validating resolver over a bogus zone: without CD it refuses
		// to hand back data at all.
		if !req.CheckingDisabled {
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			return
		}

		switch req.Question[0].Qtype {
		case dns.TypeNS:
			ns := &dns.NS{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  "ns1.broken.invalid.",
			}
			m.Answer = append(m.Answer, ns)
		case dns.TypeA:
			a := &dns.A{
				Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("192.0.2.53"),
			}
			m.Answer = append(m.Answer, a)
		}
		_ = w.WriteMsg(m)
	})

	started := make(chan struct{})
	r.srv = &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = r.srv.ActivateAndServe() }()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("test resolver did not start")
	}
	t.Cleanup(func() { _ = r.srv.Shutdown() })

	return r
}

func (r *recordingResolver) queries() []bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]bool(nil), r.cdSeen...)
}

// A validating recursive resolver SERVFAILs every name in a DNSSEC-broken zone.
// Without the CD bit the chain walk stops at "no nameserver addresses found" and
// the domain is reported indeterminate instead of bogus, which defeats the whole
// purpose of a DNSSEC troubleshooting tool. Every query this tool sends to the
// configured resolver must therefore set CD.
func TestResolveNS_SetsCheckingDisabled(t *testing.T) {
	srv := newRecordingResolver(t)
	r := NewResolver(2*time.Second, srv.addr)

	nsRecords, err := r.ResolveNS(context.Background(), "dnssec-broken.invalid.")
	if err != nil {
		t.Fatalf("ResolveNS: %v", err)
	}

	seen := srv.queries()
	if len(seen) == 0 {
		t.Fatal("test resolver received no queries")
	}
	for i, cd := range seen {
		if !cd {
			t.Errorf("query %d reached the recursive resolver without the CD bit set", i)
		}
	}
	if len(nsRecords) == 0 {
		t.Fatal("expected NS records once CD suppressed the resolver's SERVFAIL")
	}
	if nsRecords[0].Name != "ns1.broken.invalid." {
		t.Errorf("NS = %q, want ns1.broken.invalid.", nsRecords[0].Name)
	}
}

// The address lookups behind each NS name must set CD too — otherwise the NS
// records resolve but their addresses do not, and the chain still dead-ends at
// "no nameserver addresses found".
func TestResolveAddresses_SetsCheckingDisabled(t *testing.T) {
	srv := newRecordingResolver(t)
	r := NewResolver(2*time.Second, srv.addr)

	addrs, err := r.ResolveAddresses(context.Background(), "ns1.broken.invalid.")
	if err != nil {
		t.Fatalf("ResolveAddresses: %v", err)
	}

	for i, cd := range srv.queries() {
		if !cd {
			t.Errorf("address query %d reached the recursive resolver without the CD bit set", i)
		}
	}
	if len(addrs) == 0 {
		t.Fatal("expected addresses once CD suppressed the resolver's SERVFAIL")
	}
}

// CheckZoneCut drives zone discovery; a CD-less SERVFAIL there mislabels a
// broken-but-present zone.
func TestCheckZoneCut_SetsCheckingDisabled(t *testing.T) {
	srv := newRecordingResolver(t)
	r := NewResolver(2*time.Second, srv.addr)

	isCut, err := r.CheckZoneCut(context.Background(), "dnssec-broken.invalid.")
	if err != nil {
		t.Fatalf("CheckZoneCut: %v", err)
	}
	if !isCut {
		t.Error("zone with NS records should be reported as a zone cut")
	}
	for i, cd := range srv.queries() {
		if !cd {
			t.Errorf("zone-cut query %d reached the recursive resolver without the CD bit set", i)
		}
	}
}

// Authoritative servers do not validate, so CD is meaningless there; it is scoped
// to recursion so an authoritative query is byte-identical to before this change.
func TestQueryWithRecursion_CDScopedToRecursion(t *testing.T) {
	srv := newRecordingResolver(t)
	q := NewQuerier(2 * time.Second)

	if _, err := q.QueryWithRecursion(context.Background(), srv.addr, "example.invalid.", dns.TypeA, false); err != nil {
		t.Fatalf("authoritative query: %v", err)
	}
	seen := srv.queries()
	if len(seen) == 0 {
		t.Fatal("no query received")
	}
	if seen[0] {
		t.Error("authoritative query (recurse=false) must not set CD")
	}
}
