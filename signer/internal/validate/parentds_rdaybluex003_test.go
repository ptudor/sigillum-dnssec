package validate

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// RDAYBLUEX-003: nameserver discovery covers every delegated NS identity
// (truncation retried over TCP, responses validated, only in-bailiwick
// owner-matched glue, every NS resolved in both families, a name that cannot
// be resolved fails discovery by name), and direct probes require an
// authoritative answer to exactly the question asked with owner-correct
// records.

// probeLab is a programmable recursive resolver (UDP and TCP on one port)
// plus two authoritative parent servers (127.0.0.1 and ::1 on one port).
type probeLab struct {
	t        *testing.T
	mu       sync.Mutex
	resolve  func(q dns.Question, tcp bool) *dns.Msg
	auth     func(addr string, q dns.Question) *dns.Msg
	port     string
	resolver string
	servers  []*dns.Server
	queried  map[string]int // auth address → queries
}

func newProbeLab(t *testing.T) *probeLab {
	t.Helper()
	lab := &probeLab{t: t, queried: map[string]int{}}
	// Authoritative servers.
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
	for _, pc := range []net.PacketConn{pc4, pc6} {
		host, _, _ := net.SplitHostPort(pc.LocalAddr().String())
		addr := net.JoinHostPort(host, lab.port)
		srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			lab.mu.Lock()
			lab.queried[addr]++
			auth := lab.auth
			lab.mu.Unlock()
			var m *dns.Msg
			if auth != nil {
				m = auth(addr, r.Question[0])
			}
			if m == nil {
				m = new(dns.Msg)
				m.SetReply(r)
				m.Authoritative = true
			} else if m.Id == 0 {
				m.Id = r.Id
				m.Response = true
				if len(m.Question) == 0 {
					m.Question = r.Question
				}
			}
			_ = w.WriteMsg(m)
		})}
		go srv.ActivateAndServe()
		lab.servers = append(lab.servers, srv)
	}
	// Recursive resolver mock, UDP and TCP on one port.
	rpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lab.resolver = rpc.LocalAddr().String()
	ln, err := net.Listen("tcp", lab.resolver)
	if err != nil {
		t.Fatal(err)
	}
	handler := func(tcp bool) dns.HandlerFunc {
		return func(w dns.ResponseWriter, r *dns.Msg) {
			lab.mu.Lock()
			resolve := lab.resolve
			lab.mu.Unlock()
			var m *dns.Msg
			if resolve != nil {
				m = resolve(r.Question[0], tcp)
			}
			if m == nil {
				m = new(dns.Msg)
				m.SetReply(r)
			} else {
				m.Id = r.Id
				m.Response = true
				if len(m.Question) == 0 {
					m.Question = r.Question
				}
			}
			_ = w.WriteMsg(m)
		}
	}
	usrv := &dns.Server{PacketConn: rpc, Handler: handler(false)}
	tsrv := &dns.Server{Listener: ln, Handler: handler(true)}
	go usrv.ActivateAndServe()
	go tsrv.ActivateAndServe()
	lab.servers = append(lab.servers, usrv, tsrv)
	t.Cleanup(func() {
		for _, s := range lab.servers {
			s.Shutdown()
		}
	})
	time.Sleep(20 * time.Millisecond)
	return lab
}

func (l *probeLab) v4() string { return net.JoinHostPort("127.0.0.1", l.port) }
func (l *probeLab) v6() string { return net.JoinHostPort("::1", l.port) }

func (l *probeLab) validator() *Validator {
	return &Validator{resolver: l.resolver, timeout: 2 * time.Second, authPort: l.port}
}

func (l *probeLab) setResolve(fn func(q dns.Question, tcp bool) *dns.Msg) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.resolve = fn
}

func (l *probeLab) setAuth(fn func(addr string, q dns.Question) *dns.Msg) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.auth = fn
}

func (l *probeLab) queries(addr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.queried[addr]
}

// Record builders.
func nsRR(zone, ns string) dns.RR {
	return &dns.NS{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: ns}
}
func aRR(name, ip string) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}
}
func aaaaRR(name, ip string) dns.RR {
	return &dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}, AAAA: net.ParseIP(ip)}
}
func soaRR(name string, serial uint32) dns.RR {
	return &dns.SOA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.parent.test.", Mbox: "h.parent.test.", Serial: serial, Refresh: 1, Retry: 1, Expire: 1, Minttl: 1}
}

// answer builds a NOERROR response carrying the given sections.
func answer(q dns.Question, ans, ns, extra []dns.RR) *dns.Msg {
	m := new(dns.Msg)
	m.Question = []dns.Question{q}
	m.Answer, m.Ns, m.Extra = ans, ns, extra
	return m
}

// authDS is an authoritative DS answer owned by q.Name for the given keys.
func authDS(q dns.Question, keys ...*dns.DNSKEY) *dns.Msg {
	m := answer(q, nil, nil, nil)
	m.Authoritative = true
	for _, k := range keys {
		ds := k.ToDS(dns.SHA256)
		ds.Hdr.Name = q.Name
		ds.Hdr.Ttl = 3600
		m.Answer = append(m.Answer, ds)
	}
	return m
}

const parentZone = "parent.test."

// standardResolver answers NS for parent.test. with two in-bailiwick names
// and glue for both families, and resolves everything else per extra.
func (l *probeLab) standardResolver(extra func(q dns.Question, tcp bool) *dns.Msg) {
	l.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		if extra != nil {
			if m := extra(q, tcp); m != nil {
				return m
			}
		}
		if q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, parentZone) {
			return answer(q,
				[]dns.RR{nsRR(parentZone, "ns4.parent.test."), nsRR(parentZone, "ns6.parent.test.")}, nil,
				[]dns.RR{aRR("ns4.parent.test.", "127.0.0.1"), aaaaRR("ns6.parent.test.", "::1")})
		}
		return nil
	})
}

func TestRDAYBLUEX003_TruncatedResponsesRetriedOverTCP(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	// NS answer truncated on UDP; complete on TCP. The NS names are out of
	// bailiwick (ns.other.test.), so their addresses are resolved separately —
	// and those lookups are truncated on UDP too.
	lab.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		if !tcp {
			m := answer(q, nil, nil, nil)
			m.Truncated = true
			return m
		}
		switch {
		case q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, parentZone):
			return answer(q, []dns.RR{nsRR(parentZone, "ns4.other.test."), nsRR(parentZone, "ns6.other.test.")}, nil, nil)
		case q.Qtype == dns.TypeA && strings.EqualFold(q.Name, "ns4.other.test."):
			return answer(q, []dns.RR{aRR(q.Name, "127.0.0.1")}, nil, nil)
		case q.Qtype == dns.TypeAAAA && strings.EqualFold(q.Name, "ns6.other.test."):
			return answer(q, []dns.RR{aaaaRR(q.Name, "::1")}, nil, nil)
		}
		return answer(q, nil, nil, nil) // NODATA for the other family
	})
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg { return authDS(q, k) })
	v := lab.validator()
	obs, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err != nil {
		t.Fatalf("truncated NS/A/AAAA answers must be completed over TCP: %v", err)
	}
	if len(obs.Servers) != 2 || !obs.PresentOnAll[k.KeyTag()] {
		t.Fatalf("both parent servers must be discovered and probed: %+v", obs)
	}
	if len(obs.ByNameserver) != 2 || len(obs.ByNameserver["ns4.other.test."]) != 1 || len(obs.ByNameserver["ns6.other.test."]) != 1 {
		t.Fatalf("the observation must record every nameserver identity: %+v", obs.ByNameserver)
	}
}

func TestRDAYBLUEX003_UnresolvableThirdNSFailsDiscoveryByName(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	lab.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		switch {
		case q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, parentZone):
			return answer(q,
				[]dns.RR{nsRR(parentZone, "ns4.parent.test."), nsRR(parentZone, "ns6.parent.test."), nsRR(parentZone, "ns-gone.parent.test.")}, nil,
				[]dns.RR{aRR("ns4.parent.test.", "127.0.0.1"), aaaaRR("ns6.parent.test.", "::1")})
		case strings.EqualFold(q.Name, "ns-gone.parent.test."):
			m := answer(q, nil, nil, nil)
			m.Rcode = dns.RcodeNameError
			return m
		}
		return answer(q, nil, nil, nil)
	})
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg { return authDS(q) })
	v := lab.validator()
	_, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err == nil || !strings.Contains(err.Error(), "ns-gone.parent.test.") || !strings.Contains(err.Error(), "coverage incomplete") {
		t.Fatalf("discovery must fail naming the unresolved nameserver, got %v", err)
	}
	if lab.queries(lab.v4()) != 0 && lab.queries(lab.v6()) != 0 {
		t.Fatal("no DS decision may be built from the resolvable subset")
	}
	if _, _, err := v.ProbePublishedSerial("parent.test.", 1); err == nil {
		t.Fatal("publication confirmation must not proceed on a partial delegation")
	}
}

func TestRDAYBLUEX003_OneFamilyGluePlusResolvedSecondFamily(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	// One NS name with A glue only; its AAAA is resolved through the resolver.
	lab.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		switch {
		case q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, parentZone):
			return answer(q, []dns.RR{nsRR(parentZone, "ns.parent.test.")}, nil, []dns.RR{aRR("ns.parent.test.", "127.0.0.1")})
		case q.Qtype == dns.TypeAAAA && strings.EqualFold(q.Name, "ns.parent.test."):
			return answer(q, []dns.RR{aaaaRR(q.Name, "::1")}, nil, nil)
		case q.Qtype == dns.TypeA && strings.EqualFold(q.Name, "ns.parent.test."):
			t.Errorf("the A family was supplied by glue and must not be re-resolved")
		}
		return answer(q, nil, nil, nil)
	})
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg { return authDS(q, k) })
	obs, err := lab.validator().ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Servers) != 2 || lab.queries(lab.v4()) == 0 || lab.queries(lab.v6()) == 0 {
		t.Fatalf("both address families of the nameserver must be probed: %+v (v4 %d, v6 %d)", obs.Servers, lab.queries(lab.v4()), lab.queries(lab.v6()))
	}
}

func TestRDAYBLUEX003_UnrelatedAndOutOfBailiwickAdditionalIgnored(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	// The NS name is out of bailiwick; the NS answer carries an Additional A
	// for it pointing at an unroutable address, plus an unrelated record.
	// Neither may be used: the name is resolved through the resolver.
	lab.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		switch {
		case q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, parentZone):
			return answer(q, []dns.RR{nsRR(parentZone, "ns.elsewhere.test.")}, nil,
				[]dns.RR{aRR("ns.elsewhere.test.", "192.0.2.99"), aRR("unrelated.parent.test.", "192.0.2.98")})
		case q.Qtype == dns.TypeA && strings.EqualFold(q.Name, "ns.elsewhere.test."):
			return answer(q, []dns.RR{aRR(q.Name, "127.0.0.1")}, nil, nil)
		}
		return answer(q, nil, nil, nil)
	})
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg { return authDS(q, k) })
	v := lab.validator()
	v.timeout = 500 * time.Millisecond
	obs, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err != nil {
		t.Fatalf("out-of-bailiwick glue must be ignored in favour of resolution: %v", err)
	}
	if len(obs.Servers) != 1 || obs.Servers[0] != lab.v4() {
		t.Fatalf("only the resolved address may be probed, got %v", obs.Servers)
	}
}

func TestRDAYBLUEX003_SharedAddressQueriedOnceButBothIdentitiesCovered(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	lab.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		if q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, parentZone) {
			return answer(q, []dns.RR{nsRR(parentZone, "a.parent.test."), nsRR(parentZone, "b.parent.test.")}, nil,
				[]dns.RR{aRR("a.parent.test.", "127.0.0.1"), aRR("b.parent.test.", "127.0.0.1")})
		}
		return answer(q, nil, nil, nil)
	})
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg { return authDS(q, k) })
	obs, err := lab.validator().ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.Servers) != 1 || lab.queries(lab.v4()) != 1 {
		t.Fatalf("a shared address is queried once, got servers %v queries %d", obs.Servers, lab.queries(lab.v4()))
	}
	if len(obs.ByNameserver) != 2 {
		t.Fatalf("both nameserver identities must be recorded: %+v", obs.ByNameserver)
	}
}

func TestRDAYBLUEX003_NonAuthoritativeAnswerIsAnError(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	lab.standardResolver(nil)
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg {
		m := authDS(q, k)
		if addr == lab.v6() {
			m.Authoritative = false // a lame/recursive answer
		}
		return m
	})
	_, err := lab.validator().ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err == nil || !strings.Contains(err.Error(), "non-authoritative") {
		t.Fatalf("a non-authoritative answer must fail the probe, got %v", err)
	}
}

func TestRDAYBLUEX003_WrongEchoedQuestionIsAnError(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	lab.standardResolver(nil)
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg {
		m := authDS(dns.Question{Name: "other.parent.test.", Qtype: dns.TypeDS, Qclass: dns.ClassINET}, k)
		return m
	})
	_, err := lab.validator().ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err == nil || !strings.Contains(err.Error(), "not the query") {
		t.Fatalf("an answer to another question must fail the probe, got %v", err)
	}
	// The resolver side is validated too.
	lab.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		return answer(dns.Question{Name: "wrong.test.", Qtype: q.Qtype, Qclass: q.Qclass}, nil, nil, nil)
	})
	if _, err := lab.validator().ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k}); err == nil || !strings.Contains(err.Error(), "not the query") {
		t.Fatalf("a resolver answer to another question must fail discovery, got %v", err)
	}
}

func TestRDAYBLUEX003_WrongOwnerRecordsNotCounted(t *testing.T) {
	lab := newProbeLab(t)
	k := testKSK(t, 1)
	lab.standardResolver(nil)
	// DS records for the right key but owned by another name.
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg {
		switch q.Qtype {
		case dns.TypeDS:
			m := authDS(q, k)
			for _, rr := range m.Answer {
				rr.Header().Name = "other.parent.test."
			}
			return m
		case dns.TypeSOA:
			m := answer(q, []dns.RR{soaRR("other.parent.test.", 42)}, nil, nil)
			m.Authoritative = true
			return m
		}
		return nil
	})
	v := lab.validator()
	obs, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{k})
	if err != nil {
		t.Fatal(err)
	}
	if obs.PresentOnAll[k.KeyTag()] || !obs.AbsentOnAll[k.KeyTag()] || obs.TTL != 0 {
		t.Fatalf("a DS owned by another name must not count as the domain's DS: %+v", obs)
	}
	ok, details, err := v.ProbePublishedSerial("parent.test.", 42)
	if err != nil || ok || !strings.Contains(details, "no SOA") {
		t.Fatalf("an SOA owned by another name must not confirm publication (ok=%v details=%q err=%v)", ok, details, err)
	}
}

// The gates that consume the probe: with an incompletely covered delegation
// the algorithm-rollover old-DS-removal phase does not advance.
func TestRDAYBLUEX003_IncompleteCoverageDoesNotAdvanceRollover(t *testing.T) {
	lab := newProbeLab(t)
	lab.setResolve(func(q dns.Question, tcp bool) *dns.Msg {
		switch {
		case q.Qtype == dns.TypeNS && strings.EqualFold(q.Name, parentZone):
			return answer(q, []dns.RR{nsRR(parentZone, "ns4.parent.test."), nsRR(parentZone, "dead.parent.test.")}, nil,
				[]dns.RR{aRR("ns4.parent.test.", "127.0.0.1")})
		case strings.EqualFold(q.Name, "dead.parent.test."):
			m := answer(q, nil, nil, nil)
			m.Rcode = dns.RcodeServerFailure
			return m
		}
		return answer(q, nil, nil, nil)
	})
	lab.setAuth(func(addr string, q dns.Question) *dns.Msg { return authDS(q) }) // old DS absent here
	v := lab.validator()
	obs, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{testKSK(t, 1)})
	if err == nil {
		t.Fatalf("the probe must fail on incomplete coverage, got %+v", obs)
	}
	// The rollover consumer treats a probe error as "no decision": the
	// signer-side check is exercised through its exported gate in
	// publication tests; here the contract is that AbsentOnAll is never
	// reported true from a partial view.
	if obs.AbsentOnAll[testKSK(t, 1).KeyTag()] {
		t.Fatal("absence must not be asserted from a partial delegation view")
	}
}
