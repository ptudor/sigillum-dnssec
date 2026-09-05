package validate

import (
	"crypto/ed25519"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// servedZone is a hermetic authoritative server for one signed zone plus its
// parent's DS RRset, with a resolver mock that points every NS lookup at it.
// What it serves is mutable so each case can break one thing.
type servedZone struct {
	mu               sync.Mutex
	domain           string
	dnskeys          []dns.RR
	dnskeySigs       []dns.RR
	soa              []dns.RR
	soaSigs          []dns.RR
	parentDS         []dns.RR
	port             string
	resolver         string
	servers          []*dns.Server
	v                *Validator
	cfg              *config.Config
	state            *statepkg.State
	ksk, zsk         *dns.DNSKEY
	kskPriv, zskPriv ed25519.PrivateKey
}

func newServedZone(t *testing.T) *servedZone {
	t.Helper()
	dir := t.TempDir()
	cfg := dnssectest.Config(t, dir)
	cfg.DNSSEC.SignatureRefresh = config.Duration{Duration: time.Hour}
	domain := "signed.example"
	if err := signerpkg.EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	kg := signerpkg.NewKeyGenerator(cfg)
	kskState, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zskState, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	ksk, kskPriv, err := kg.LoadKeyPair(domain, "ksk")
	if err != nil {
		t.Fatal(err)
	}
	zsk, zskPriv, err := kg.LoadKeyPair(domain, "zsk")
	if err != nil {
		t.Fatal(err)
	}
	st := statepkg.NewState(cfg.StatePath())
	st.SetZone(domain, &statepkg.ZoneState{Path: "/unused", KSK: kskState, ZSK: zskState, Serial: 7, PublishedSerial: 7})

	z := &servedZone{domain: domain, cfg: cfg, state: st, ksk: ksk, zsk: zsk, kskPriv: ed25519.PrivateKey(kskPriv), zskPriv: ed25519.PrivateKey(zskPriv)}
	z.ksk.Hdr.Ttl, z.zsk.Hdr.Ttl = 3600, 3600
	z.dnskeys = []dns.RR{z.ksk, z.zsk}
	z.soa = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns: "ns1." + dns.Fqdn(domain), Mbox: "admin." + dns.Fqdn(domain), Serial: 7, Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 300}}
	z.resignAll(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	z.parentDS = []dns.RR{z.ksk.ToDS(dns.SHA256)}
	z.parentDS[0].Header().Ttl = 3600

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, z.port, _ = net.SplitHostPort(pc.LocalAddr().String())
	authStarted := make(chan struct{})
	auth := &dns.Server{PacketConn: pc, NotifyStartedFunc: func() { close(authStarted) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		z.mu.Lock()
		defer z.mu.Unlock()
		q := r.Question[0]
		switch q.Qtype {
		case dns.TypeDS:
			m.Answer = append(m.Answer, z.parentDS...)
		case dns.TypeDNSKEY:
			m.Answer = append(append(m.Answer, z.dnskeys...), z.dnskeySigs...)
		case dns.TypeSOA:
			m.Answer = append(append(m.Answer, z.soa...), z.soaSigs...)
		}
		w.WriteMsg(m)
	})}
	go auth.ActivateAndServe()
	rpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	z.resolver = rpc.LocalAddr().String()
	resStarted := make(chan struct{})
	res := &dns.Server{PacketConn: rpc, NotifyStartedFunc: func() { close(resStarted) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		if q.Qtype == dns.TypeNS {
			m.Answer = append(m.Answer, &dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.lab."})
			m.Extra = append(m.Extra, &dns.A{Hdr: dns.RR_Header{Name: "ns.lab.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("127.0.0.1")})
		}
		w.WriteMsg(m)
	})}
	go res.ActivateAndServe()
	<-authStarted
	<-resStarted
	z.servers = []*dns.Server{auth, res}
	t.Cleanup(func() {
		for _, s := range z.servers {
			s.Shutdown()
		}
	})
	z.v = &Validator{cfg: cfg, state: st, resolver: z.resolver, timeout: 2 * time.Second, authPort: z.port}
	return z
}

func (z *servedZone) sign(t *testing.T, rrset []dns.RR, key *dns.DNSKEY, priv ed25519.PrivateKey, inc, exp time.Time) *dns.RRSIG {
	t.Helper()
	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl},
		TypeCovered: rrset[0].Header().Rrtype, Algorithm: dns.ED25519, Labels: uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl: rrset[0].Header().Ttl, Expiration: uint32(exp.Unix()), Inception: uint32(inc.Unix()), KeyTag: key.KeyTag(), SignerName: rrset[0].Header().Name,
	}
	if err := rrsig.Sign(priv, rrset); err != nil {
		t.Fatal(err)
	}
	return rrsig
}

func (z *servedZone) resignAll(t *testing.T, inc, exp time.Time) {
	t.Helper()
	z.dnskeySigs = []dns.RR{z.sign(t, z.dnskeys, z.ksk, z.kskPriv, inc, exp)}
	z.soaSigs = []dns.RR{z.sign(t, z.soa, z.zsk, z.zskPriv, inc, exp)}
}

// edit mutates what the server serves under the handler's lock.
func (z *servedZone) edit(fn func()) {
	z.mu.Lock()
	defer z.mu.Unlock()
	fn()
}

func corrupt(sig *dns.RRSIG) {
	b := []byte(sig.Signature)
	if b[0] == 'A' {
		b[0] = 'B'
	} else {
		b[0] = 'A'
	}
	sig.Signature = string(b)
}

func TestValidateZone_CryptographicVerdicts(t *testing.T) {
	t.Run("valid zone passes", func(t *testing.T) {
		z := newServedZone(t)
		r := z.v.ValidateZone(z.domain)
		if r.Overall != "pass" || r.Servfail || !r.RRSIGCheck.Verified || !r.DNSKEYCheck.MaterialMatched {
			t.Fatalf("valid zone: %+v", r)
		}
	})
	t.Run("corrupt SOA signature with matching tag and window fails", func(t *testing.T) {
		z := newServedZone(t)
		z.edit(func() { corrupt(z.soaSigs[0].(*dns.RRSIG)) })
		r := z.v.ValidateZone(z.domain)
		if r.Overall != "fail" || !r.Servfail || r.RRSIGCheck.SOASigned || !r.RRSIGCheck.Broken {
			t.Fatalf("corrupt signature must fail: %+v", r.RRSIGCheck)
		}
	})
	t.Run("empty DNSKEY signature fails", func(t *testing.T) {
		z := newServedZone(t)
		z.edit(func() { z.dnskeySigs[0].(*dns.RRSIG).Signature = "" })
		r := z.v.ValidateZone(z.domain)
		if r.Overall != "fail" || !r.Servfail || r.RRSIGCheck.DNSKEYSigned {
			t.Fatalf("empty signature must fail: %+v", r.RRSIGCheck)
		}
	})
	t.Run("served key with other material than ours is not our key", func(t *testing.T) {
		z := newServedZone(t)
		impostor := newSignedFixture(t, dns.Fqdn(z.domain), 256)
		z.edit(func() {
			z.dnskeys = []dns.RR{z.ksk, impostor.key}
			z.resignAll(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
			z.soaSigs = []dns.RR{impostor.sign(t, z.soa, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))}
		})
		r := z.v.ValidateZone(z.domain)
		if r.DNSKEYCheck.ZSKFound {
			t.Fatal("a different key must not count as our ZSK")
		}
		if r.Overall != "fail" || !r.Servfail {
			t.Fatalf("SOA signed only by a foreign key under a DS must fail: %+v", r)
		}
	})
	t.Run("mismatching parent DS fails, not partial", func(t *testing.T) {
		z := newServedZone(t)
		other := newSignedFixture(t, dns.Fqdn(z.domain), 257)
		z.edit(func() { z.parentDS = []dns.RR{other.key.ToDS(dns.SHA256)} })
		r := z.v.ValidateZone(z.domain)
		if r.Overall != "fail" || !r.Servfail || r.DSCheck.MatchesKSK {
			t.Fatalf("a DS authenticating none of our keys is a broken chain: overall=%s ds=%+v", r.Overall, r.DSCheck)
		}
	})
	t.Run("exactly one missing required signature fails under a DS", func(t *testing.T) {
		z := newServedZone(t)
		z.edit(func() { z.dnskeySigs = nil })
		r := z.v.ValidateZone(z.domain)
		if r.Overall != "fail" || !r.Servfail || r.RRSIGCheck.Status != "partial" || !r.RRSIGCheck.Broken {
			t.Fatalf("one missing signature with a DS present must fail: overall=%s rrsig=%+v", r.Overall, r.RRSIGCheck)
		}
	})
	t.Run("dual-signature KSK rollover passes", func(t *testing.T) {
		z := newServedZone(t)
		// Old KSK backed up on disk and named by the rollover record; the
		// served DNSKEY RRset carries both KSKs and is signed by both.
		kg := signerpkg.NewKeyGenerator(z.cfg)
		zs := z.state.GetZone(z.domain)
		rm := signerpkg.NewRolloverManager(z.cfg, z.state)
		if err := rm.StartKSKRollover(z.domain); err != nil {
			t.Fatal(err)
		}
		newKSK, newPriv, err := kg.LoadKeyPair(z.domain, "ksk")
		if err != nil {
			t.Fatal(err)
		}
		newKSK.Hdr.Ttl = 3600
		now := time.Now()
		z.edit(func() {
			z.dnskeys = []dns.RR{z.ksk, newKSK, z.zsk}
			z.dnskeySigs = []dns.RR{
				z.sign(t, z.dnskeys, z.ksk, z.kskPriv, now.Add(-time.Hour), now.Add(24*time.Hour)),
				z.sign(t, z.dnskeys, newKSK, ed25519.PrivateKey(newPriv), now.Add(-time.Hour), now.Add(24*time.Hour)),
			}
			z.parentDS = []dns.RR{z.ksk.ToDS(dns.SHA256)} // parent still holds the old DS only
		})
		_ = zs
		r := z.v.ValidateZone(z.domain)
		if r.Overall != "pass" || r.Servfail {
			t.Fatalf("a valid dual-signature rollover must pass: overall=%s rrsig=%+v ds=%+v dnskey=%+v", r.Overall, r.RRSIGCheck, r.DSCheck, r.DNSKEYCheck)
		}
	})
	t.Run("refresh window stays partial", func(t *testing.T) {
		z := newServedZone(t)
		z.edit(func() { z.resignAll(t, time.Now().Add(-time.Hour), time.Now().Add(10*time.Minute)) })
		r := z.v.ValidateZone(z.domain)
		if r.Overall != "partial" || r.Servfail || r.RRSIGCheck.Broken {
			t.Fatalf("approaching refresh must stay partial: overall=%s rrsig=%+v", r.Overall, r.RRSIGCheck)
		}
	})
	t.Run("resolver outage is uncertain, not SERVFAIL", func(t *testing.T) {
		z := newServedZone(t)
		z.servers[1].Shutdown() // the recursive resolver mock
		z.v.timeout = 300 * time.Millisecond
		r := z.v.ValidateZone(z.domain)
		if r.Overall != "error" || r.Servfail || !r.ResolverOutage {
			t.Fatalf("a resolver outage must be reported as uncertain: overall=%s servfail=%v outage=%v", r.Overall, r.Servfail, r.ResolverOutage)
		}
	})
}
