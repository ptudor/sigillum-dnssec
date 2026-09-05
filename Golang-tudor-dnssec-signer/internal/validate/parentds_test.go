package validate

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// parentLab is a hermetic parent zone with two authoritative servers (one on
// 127.0.0.1, one on ::1, same port) and a recursive resolver mock that hands
// out their NS and glue.
type parentLab struct {
	mu        sync.Mutex
	dsByAddr  map[string][]*dns.DS // per auth server address
	soaByAddr map[string]uint32
	port      string
	resolver  string
	servers   []*dns.Server
}

func newParentLab(t *testing.T) *parentLab {
	t.Helper()
	lab := &parentLab{dsByAddr: map[string][]*dns.DS{}, soaByAddr: map[string]uint32{}}
	var pc4, pc6 net.PacketConn
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		pc4, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, _ := net.SplitHostPort(pc4.LocalAddr().String())
		pc6, err = net.ListenPacket("udp", net.JoinHostPort("::1", port))
		if err == nil {
			lab.port = port
			break
		}
		pc4.Close()
	}
	if pc6 == nil {
		t.Skip("could not bind the same port on 127.0.0.1 and ::1")
	}
	auth := func(addr string) dns.HandlerFunc {
		return func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			lab.mu.Lock()
			defer lab.mu.Unlock()
			q := r.Question[0]
			switch q.Qtype {
			case dns.TypeDS:
				for _, ds := range lab.dsByAddr[addr] {
					cp := dns.Copy(ds).(*dns.DS)
					cp.Hdr.Name = q.Name
					m.Answer = append(m.Answer, cp)
				}
			case dns.TypeSOA:
				if serial, ok := lab.soaByAddr[addr]; ok {
					m.Answer = append(m.Answer, &dns.SOA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns1.parent.test.", Mbox: "h.parent.test.", Serial: serial, Refresh: 1, Retry: 1, Expire: 1, Minttl: 1})
				}
			}
			w.WriteMsg(m)
		}
	}
	for _, pc := range []net.PacketConn{pc4, pc6} {
		host, _, _ := net.SplitHostPort(pc.LocalAddr().String())
		addr := net.JoinHostPort(host, lab.port)
		srv := &dns.Server{PacketConn: pc, Handler: auth(addr)}
		go srv.ActivateAndServe()
		lab.servers = append(lab.servers, srv)
	}
	// Recursive resolver mock: NS for any zone → ns4/ns6 with glue.
	rpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lab.resolver = rpc.LocalAddr().String()
	rsrv := &dns.Server{PacketConn: rpc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeNS {
			m.Answer = append(m.Answer,
				&dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns4.lab."},
				&dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns6.lab."})
			m.Extra = append(m.Extra,
				&dns.A{Hdr: dns.RR_Header{Name: "ns4.lab.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")},
				&dns.AAAA{Hdr: dns.RR_Header{Name: "ns6.lab.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP("::1")})
		}
		w.WriteMsg(m)
	})}
	go rsrv.ActivateAndServe()
	lab.servers = append(lab.servers, rsrv)
	t.Cleanup(func() {
		for _, s := range lab.servers {
			s.Shutdown()
		}
	})
	return lab
}

func (l *parentLab) v4() string { return net.JoinHostPort("127.0.0.1", l.port) }
func (l *parentLab) v6() string { return net.JoinHostPort("::1", l.port) }

func (l *parentLab) set(addr string, ds ...*dns.DS) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dsByAddr[addr] = ds
}

func (l *parentLab) validator() *Validator {
	return &Validator{resolver: l.resolver, timeout: 2 * time.Second, authPort: l.port}
}

func testKSK(t *testing.T, tag int) *dns.DNSKEY {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "child.parent.test.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519}
	_, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	_ = tag
	return k
}

func dsWithTTL(k *dns.DNSKEY, ttl uint32) *dns.DS {
	ds := k.ToDS(dns.SHA256)
	ds.Hdr.Ttl = ttl
	return ds
}

func TestProbeParentDS_AllServersMustAgree(t *testing.T) {
	lab := newParentLab(t)
	v := lab.validator()
	oldK, newK := testKSK(t, 1), testKSK(t, 2)

	// Only one parent server has the new DS yet.
	lab.set(lab.v4(), dsWithTTL(oldK, 3600), dsWithTTL(newK, 3600))
	lab.set(lab.v6(), dsWithTTL(oldK, 7200))
	obs, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{oldK, newK})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Servers) != 2 {
		t.Fatalf("both parent servers must be queried, got %v", obs.Servers)
	}
	if obs.PresentOnAll[newK.KeyTag()] || obs.AbsentOnAll[newK.KeyTag()] {
		t.Fatalf("a DS present on one server only is neither present-on-all nor absent-on-all: %+v", obs)
	}
	if !obs.PresentOnAll[oldK.KeyTag()] {
		t.Fatal("the old DS is on every server")
	}
	if obs.TTL != 7200 {
		t.Fatalf("the largest DS TTL must be reported, got %d", obs.TTL)
	}

	// Propagated everywhere.
	lab.set(lab.v6(), dsWithTTL(oldK, 7200), dsWithTTL(newK, 7200))
	obs, err = v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{newK})
	if err != nil || !obs.PresentOnAll[newK.KeyTag()] {
		t.Fatalf("the new DS must be present on all servers now (err %v, obs %+v)", err, obs)
	}

	// Old DS removed everywhere.
	lab.set(lab.v4(), dsWithTTL(newK, 3600))
	lab.set(lab.v6(), dsWithTTL(newK, 7200))
	obs, err = v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{oldK})
	if err != nil || !obs.AbsentOnAll[oldK.KeyTag()] {
		t.Fatalf("the old DS must be absent on all servers (err %v, obs %+v)", err, obs)
	}

	// An unreachable server is an error, never a partial verdict.
	lab.servers[1].Shutdown()
	v.timeout = 300 * time.Millisecond
	if _, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{newK}); err == nil {
		t.Fatal("a parent server that cannot be queried must fail the probe")
	}
}

func TestProbePublishedSerial_AllServersMustServeIt(t *testing.T) {
	lab := newParentLab(t)
	v := lab.validator()
	lab.mu.Lock()
	lab.soaByAddr[lab.v4()] = 1700000002
	lab.soaByAddr[lab.v6()] = 1700000001
	lab.mu.Unlock()
	ok, details, err := v.ProbePublishedSerial("child.parent.test.", 1700000002)
	if err != nil || ok {
		t.Fatalf("one server still on the old serial must not confirm (ok=%v details=%q err=%v)", ok, details, err)
	}
	lab.mu.Lock()
	lab.soaByAddr[lab.v6()] = 1700000002
	lab.mu.Unlock()
	ok, details, err = v.ProbePublishedSerial("child.parent.test.", 1700000002)
	if err != nil || !ok {
		t.Fatalf("all servers on the published serial must confirm (details=%q err=%v)", details, err)
	}
}
