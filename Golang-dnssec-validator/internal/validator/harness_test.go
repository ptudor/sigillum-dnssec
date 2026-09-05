package validator

import (
	"context"
	"crypto"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// This file is the hermetic caller-level harness the Astra 6 review asked for
// (RA6X-050): a loopback DNS server that stands in for the recursive resolver
// AND for every authoritative server the validator discovers, so crafted,
// genuinely signed responses can be driven through the real orchestration
// path (validateZone, verifyActualRecord, Validate) without any network.

// qkey identifies a question the mock knows how to answer.
type qkey struct {
	name  string
	qtype uint16
}

// mockDNS is a hermetic loopback DNS server.
type mockDNS struct {
	t    *testing.T
	srv  *dns.Server
	ip   string
	port string

	tcp *dns.Server

	mu       sync.Mutex
	handlers map[qkey]func(req *dns.Msg) *dns.Msg
	dropped  map[qkey]bool // questions that get no reply at all
	truncate map[qkey]bool // questions answered truncated (empty) over UDP only
	seen     []dns.Question
}

// newMockDNS starts a DNS server on an ephemeral loopback port over both UDP
// and TCP. Questions without a registered handler get an empty NOERROR answer.
func newMockDNS(t *testing.T) *mockDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	m := &mockDNS{
		t: t, ip: host, port: port,
		handlers: make(map[qkey]func(*dns.Msg) *dns.Msg),
		dropped:  make(map[qkey]bool),
		truncate: make(map[qkey]bool),
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) != 1 {
			return
		}
		q := req.Question[0]
		key := qkey{dns.CanonicalName(q.Name), q.Qtype}
		m.mu.Lock()
		m.seen = append(m.seen, q)
		h := m.handlers[key]
		drop := m.dropped[key]
		trunc := m.truncate[key]
		m.mu.Unlock()

		if drop {
			return // simulate a server that never answers
		}
		if trunc && w.RemoteAddr().Network() == "udp" {
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Truncated = true
			_ = w.WriteMsg(resp)
			return
		}

		var resp *dns.Msg
		if h != nil {
			resp = h(req)
		}
		if resp == nil {
			resp = new(dns.Msg)
			resp.SetReply(req)
		} else {
			// SetReply fixes up the header fields but also resets Rcode to
			// NOERROR; keep the handler's rcode and sections.
			rcode := resp.Rcode
			resp.SetReply(req)
			resp.Rcode = rcode
		}
		resp.Authoritative = true
		if opt := req.IsEdns0(); opt != nil {
			resp.SetEdns0(4096, opt.Do())
		}
		_ = w.WriteMsg(resp)
	})

	started := make(chan struct{})
	m.srv = &dns.Server{PacketConn: pc, Handler: mux, NotifyStartedFunc: func() { close(started) }}
	go func() { _ = m.srv.ActivateAndServe() }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("mock DNS server did not start")
	}
	startedTCP := make(chan struct{})
	m.tcp = &dns.Server{Listener: ln, Handler: mux, NotifyStartedFunc: func() { close(startedTCP) }}
	go func() { _ = m.tcp.ActivateAndServe() }()
	select {
	case <-startedTCP:
	case <-time.After(5 * time.Second):
		t.Fatal("mock DNS TCP server did not start")
	}
	t.Cleanup(func() { _ = m.srv.Shutdown(); _ = m.tcp.Shutdown() })
	return m
}

// drop makes the mock never answer the question (client-side timeout).
func (m *mockDNS) drop(name string, qtype uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dropped[qkey{dns.CanonicalName(name), qtype}] = true
}

// truncateOverUDP makes the mock answer the question truncated and empty over
// UDP while serving the registered handler's full answer over TCP.
func (m *mockDNS) truncateOverUDP(name string, qtype uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.truncate[qkey{dns.CanonicalName(name), qtype}] = true
}

// on registers a handler for one question. The handler returns a message whose
// Rcode and sections are used as the response.
func (m *mockDNS) on(name string, qtype uint16, fn func(req *dns.Msg) *dns.Msg) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handlers[qkey{dns.CanonicalName(name), qtype}] = fn
}

// answer registers a NOERROR response with the given Answer-section records.
func (m *mockDNS) answer(name string, qtype uint16, rrs ...dns.RR) {
	m.on(name, qtype, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = append(resp.Answer, rrs...)
		return resp
	})
}

// respond registers a fully specified response: rcode plus the three sections.
func (m *mockDNS) respond(name string, qtype uint16, rcode int, answer, authority, additional []dns.RR) {
	m.on(name, qtype, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Rcode = rcode
		resp.Answer = append(resp.Answer, answer...)
		resp.Ns = append(resp.Ns, authority...)
		resp.Extra = append(resp.Extra, additional...)
		return resp
	})
}

// serveInfra makes the mock answer the recursive infrastructure questions for
// zone: NS zone → ns.<zone>, and A ns.<zone> → the mock's own address. AAAA
// gets an empty NOERROR by default.
func (m *mockDNS) serveInfra(zone string) {
	zone = dns.Fqdn(zone)
	nsName := "ns." + strings.TrimPrefix(zone, ".")
	if zone == "." {
		nsName = "ns.root-fixture.invalid."
	}
	m.answer(zone, dns.TypeNS, &dns.NS{Hdr: rrHdr(zone, dns.TypeNS), Ns: nsName})
	m.answer(nsName, dns.TypeA, &dns.A{Hdr: rrHdr(nsName, dns.TypeA), A: net.ParseIP(m.ip)})
}

// questions returns a copy of every question the mock has received.
func (m *mockDNS) questions() []dns.Question {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]dns.Question(nil), m.seen...)
}

// newValidator builds a Validator whose recursive resolver, authoritative
// servers and root servers are all the mock, using the port seam.
func (m *mockDNS) newValidator() *Validator {
	return m.newValidatorWithTimeout(2 * time.Second)
}

// newValidatorWithTimeout is newValidator with an explicit per-query timeout.
func (m *mockDNS) newValidatorWithTimeout(queryTimeout time.Duration) *Validator {
	v := NewValidator(queryTimeout, 20*time.Second, 4, &dnspkg.RootAnchors{Zone: "."}, m.ip)
	v.resolver.SetDefaultPort(m.port)
	v.rootServers = []string{m.ip}
	v.SetQuickMode(false)
	return v
}

// chainFixture drives the full validateWithCache path hermetically. The root
// and the TLD-like parent "test." are seeded into the validated-zone cache as
// secure zones holding the fixture's keys (the cache is an existing seam of
// the walk), so everything from the delegation to the leaf — DS at the parent,
// DNSKEY, leaf records, aliases — is fetched and verified live from the mock.
type chainFixture struct {
	m      *mockDNS
	root   *testZone
	parent *testZone
	v      *Validator
	zones  map[string]*testZone
}

func newChainFixture(t *testing.T) *chainFixture {
	t.Helper()
	m := newMockDNS(t)
	f := &chainFixture{
		m:      m,
		root:   newTestZone(t, "."),
		parent: newTestZone(t, "test."),
		zones:  make(map[string]*testZone),
	}
	m.serveInfra("test.")
	f.useTimeout(2 * time.Second)
	return f
}

// useTimeout rebuilds the fixture's validator with the given per-query timeout.
func (f *chainFixture) useTimeout(d time.Duration) {
	f.v = f.m.newValidatorWithTimeout(d)
	// The walk refuses to start without an anchor set; the root itself is
	// served from the cache below, so any pinned anchor satisfies the gate.
	f.v.SetAnchors(&dnspkg.RootAnchors{Zone: ".", Anchors: []dnspkg.Anchor{
		{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z"},
	}})
}

// addChild delegates a signed child of test. and serves its DNSKEY.
func (f *chainFixture) addChild(t *testing.T, name string) *testZone {
	t.Helper()
	z := newTestZone(t, name)
	f.zones[dns.Fqdn(name)] = z
	f.m.serveInfra(name)
	f.parent.serveDS(t, f.m, z, nil, nil)
	z.serveDNSKEY(t, f.m)
	return z
}

// addInsecureChild delegates an unsigned child of test.: the parent proves DS
// absence with a signed delegation NSEC.
func (f *chainFixture) addInsecureChild(t *testing.T, name string) *testZone {
	t.Helper()
	z := newTestZone(t, name)
	f.zones[dns.Fqdn(name)] = z
	f.m.serveInfra(name)
	deleg := nsecRR(name, "zzz.test.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)
	f.m.respond(name, dns.TypeDS, dns.RcodeSuccess, nil, f.parent.signedAuthority(t, deleg), nil)
	return z
}

// seedCache returns a fresh validated-zone cache holding the secure root and
// parent so each validation run starts from the same trusted state.
func (f *chainFixture) seedCache() map[string]*ZoneResult {
	mk := func(zone string, keys []dnspkg.DNSKEYRecord) *ZoneResult {
		zr := NewZoneResult(zone)
		zr.Status = StatusSecure
		zr.DNSKEY = keys
		return zr
	}
	return map[string]*ZoneResult{
		".":     mk(".", f.root.keyRecords()),
		"test.": mk("test.", f.parent.keyRecords()),
	}
}

// validate runs the full validation for domain.
func (f *chainFixture) validate(t *testing.T, domain string) *ValidationResult {
	t.Helper()
	res, err := f.v.validateWithCache(testCtx(t), domain, 0, make(map[string]bool), f.seedCache())
	if err != nil && res == nil {
		t.Fatalf("validate %s: %v", domain, err)
	}
	return res
}

func rrHdr(name string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: rrtype, Class: dns.ClassINET, Ttl: 300}
}

// testZone is a signed test zone: an ECDSA P-256 KSK and ZSK with signers.
type testZone struct {
	name      string
	ksk, zsk  *dns.DNSKEY
	kskSigner crypto.Signer
	zskSigner crypto.Signer
}

func newTestZone(t *testing.T, name string) *testZone {
	t.Helper()
	name = dns.Fqdn(name)
	z := &testZone{name: name}
	z.ksk, z.kskSigner = genSigningKey(t, name, 257)
	z.zsk, z.zskSigner = genSigningKey(t, name, 256)
	return z
}

func genSigningKey(t *testing.T, zone string, flags uint16) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatal("generated key is not a crypto.Signer")
	}
	return k, signer
}

// dnskeyRRset returns the zone's DNSKEY RRset as wire records.
func (z *testZone) dnskeyRRset() []dns.RR {
	return []dns.RR{z.ksk, z.zsk}
}

// keyRecords returns the parsed-style DNSKEY records a real Answer-section parse
// of the zone's DNSKEY RRset would produce.
func (z *testZone) keyRecords() []dnspkg.DNSKEYRecord {
	return []dnspkg.DNSKEYRecord{
		dnspkg.DNSKEYFromRR(z.ksk, dnspkg.SectionAnswer),
		dnspkg.DNSKEYFromRR(z.zsk, dnspkg.SectionAnswer),
	}
}

// ds returns the SHA-256 DS record for the zone's KSK.
func (z *testZone) ds(t *testing.T) *dns.DS {
	t.Helper()
	d := z.ksk.ToDS(dns.SHA256)
	if d == nil {
		t.Fatal("ToDS returned nil")
	}
	d.Hdr.Ttl = 300
	return d
}

// signWith signs rrs (one RRset) with the given key/signer, naming the zone as
// signer. Labels is derived from the owner (wildcard label excluded).
func signWith(t *testing.T, zone string, key *dns.DNSKEY, signer crypto.Signer, rrs []dns.RR) *dns.RRSIG {
	t.Helper()
	if len(rrs) == 0 {
		t.Fatal("signWith: empty RRset")
	}
	owner := rrs[0].Header().Name
	labels := dns.CountLabel(owner)
	if strings.HasPrefix(owner, "*.") {
		labels--
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrs[0].Header().Ttl},
		TypeCovered: rrs[0].Header().Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(labels),
		OrigTtl:     rrs[0].Header().Ttl,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  dns.Fqdn(zone),
	}
	if err := sig.Sign(signer, rrs); err != nil {
		t.Fatalf("sign %s %s: %v", owner, dns.TypeToString[sig.TypeCovered], err)
	}
	return sig
}

// signKSK signs rrs with the zone's KSK.
func (z *testZone) signKSK(t *testing.T, rrs ...dns.RR) *dns.RRSIG {
	return signWith(t, z.name, z.ksk, z.kskSigner, rrs)
}

// signZSK signs rrs with the zone's ZSK.
func (z *testZone) signZSK(t *testing.T, rrs ...dns.RR) *dns.RRSIG {
	return signWith(t, z.name, z.zsk, z.zskSigner, rrs)
}

// serveDNSKEY makes the mock serve the zone's DNSKEY RRset signed by its KSK.
func (z *testZone) serveDNSKEY(t *testing.T, m *mockDNS) {
	t.Helper()
	rrset := z.dnskeyRRset()
	sig := z.signKSK(t, rrset...)
	m.answer(z.name, dns.TypeDNSKEY, append(rrset, sig)...)
}

// serveDS makes parent serve the signed DS RRset for child, with optional extra
// Authority/Additional records (the injection surface under test).
func (parent *testZone) serveDS(t *testing.T, m *mockDNS, child *testZone, authority, additional []dns.RR) {
	t.Helper()
	ds := child.ds(t)
	sig := parent.signZSK(t, ds)
	m.respond(child.name, dns.TypeDS, dns.RcodeSuccess, []dns.RR{ds, sig}, authority, additional)
}

// testCtx returns a context bounded for a hermetic test.
func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}
