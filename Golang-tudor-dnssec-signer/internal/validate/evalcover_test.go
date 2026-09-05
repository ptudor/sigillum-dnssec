package validate

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// signedFixture is a zone key plus a helper that produces real RRSIGs over a
// SOA RRset, so evalRRSIGCover is exercised cryptographically (RA6X-032).
type signedFixture struct {
	key  *dns.DNSKEY
	priv ed25519.PrivateKey
	soa  []dns.RR
}

func newSignedFixture(t *testing.T, owner string, flags uint16) *signedFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: owner, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	soa := []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: owner, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1." + owner,
		Mbox:    "admin." + owner,
		Serial:  2024010101,
		Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 300,
	}}
	return &signedFixture{key: key, priv: priv, soa: soa}
}

// sign produces an RRSIG over rrset with the fixture key and the given window.
func (f *signedFixture) sign(t *testing.T, rrset []dns.RR, inc, exp time.Time) *dns.RRSIG {
	t.Helper()
	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: rrset[0].Header().Ttl},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   dns.ED25519,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(exp.Unix()),
		Inception:   uint32(inc.Unix()),
		KeyTag:      f.key.KeyTag(),
		SignerName:  rrset[0].Header().Name,
	}
	if err := rrsig.Sign(f.priv, rrset); err != nil {
		t.Fatal(err)
	}
	return rrsig
}

// --- Item 10: evalRRSIGCover must be order-independent ---

// RFC 4035 §5.3.3: a resolver accepts an RRset when ANY one covering RRSIG
// validates. An expired RRSIG preceding a valid one must not leave
// expired=true; the struct's contract is that expired/broken mean "ALL".
func TestEvalRRSIGCover_OrderIndependence(t *testing.T) {
	now := time.Now()
	f := newSignedFixture(t, "example.com.", 256)
	valid := f.sign(t, f.soa, now.Add(-time.Hour), now.Add(24*time.Hour))
	expired := f.sign(t, f.soa, now.Add(-48*time.Hour), now.Add(-time.Hour))
	validExp := time.Unix(int64(valid.Expiration), 0).UTC()
	keys := []*dns.DNSKEY{f.key}

	assertValid := func(t *testing.T, e rrsigEval) {
		t.Helper()
		if !e.valid {
			t.Error("an in-window verifying RRSIG must make the RRset valid regardless of RR order")
		}
		if e.expired || e.broken {
			t.Error("expired/broken must mean ALL signatures; a valid one clears them")
		}
		if !e.expiredExp.IsZero() {
			t.Errorf("stale earliest-expiry must not survive a valid signature: %v", e.expiredExp)
		}
		if !e.validExp.Equal(validExp) {
			t.Errorf("validExp = %v, want %v", e.validExp, validExp)
		}
	}

	t.Run("expired before valid counts as valid, not expired", func(t *testing.T) {
		assertValid(t, evalRRSIGCover(append(append([]dns.RR{}, f.soa...), expired, valid), dns.TypeSOA, keys, now))
	})

	t.Run("valid before expired gives the same result", func(t *testing.T) {
		assertValid(t, evalRRSIGCover(append(append([]dns.RR{}, f.soa...), valid, expired), dns.TypeSOA, keys, now))
	})

	t.Run("all expired still reports expired with the earliest expiry", func(t *testing.T) {
		older := f.sign(t, f.soa, now.Add(-48*time.Hour), now.Add(-2*time.Hour))
		e := evalRRSIGCover(append(append([]dns.RR{}, f.soa...), expired, older), dns.TypeSOA, keys, now)
		if e.valid || !e.present || !e.expired {
			t.Errorf("all-expired should be present+expired, not valid: present=%v valid=%v expired=%v",
				e.present, e.valid, e.expired)
		}
		want := time.Unix(int64(older.Expiration), 0).UTC()
		if !e.expiredExp.Equal(want) {
			t.Errorf("earliest expiry must be reported: got %v, want %v", e.expiredExp, want)
		}
	})
}
