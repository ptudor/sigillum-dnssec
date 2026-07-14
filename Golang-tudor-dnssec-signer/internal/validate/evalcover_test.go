package validate

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- Item 10: evalRRSIGCover must be order-independent ---

// RFC 4035 §5.3.3: a resolver accepts an RRset when ANY one covering RRSIG
// validates. Pre-fix, an expired RRSIG preceding a valid one left
// expired=true on the eval, and checkRRSIGPresent reported a hard fail
// ("resolvers will SERVFAIL") for a zone resolvers accept — while reporting
// soa_signed=true in the same output. The struct's own contract is that
// expired means "present but ALL out of window".
func TestEvalRRSIGCover_OrderIndependence(t *testing.T) {
	now := time.Now()
	mk := func(covered, tag uint16, exp, inc time.Time) *dns.RRSIG {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET},
			TypeCovered: covered,
			Algorithm:   dns.ED25519,
			KeyTag:      tag,
			SignerName:  "example.com.",
			Inception:   uint32(inc.Unix()),
			Expiration:  uint32(exp.Unix()),
		}
	}
	valid := mk(dns.TypeSOA, 111, now.Add(24*time.Hour), now.Add(-time.Hour))
	expired := mk(dns.TypeSOA, 111, now.Add(-time.Hour), now.Add(-48*time.Hour))
	validExp := time.Unix(int64(valid.Expiration), 0).UTC()

	assertValid := func(t *testing.T, e rrsigEval) {
		t.Helper()
		if !e.valid {
			t.Error("an in-window RRSIG must make the RRset valid regardless of RR order")
		}
		if e.expired {
			t.Error("expired must mean ALL signatures out of window; a valid one clears it")
		}
		if !e.expiredExp.IsZero() {
			t.Errorf("stale earliest-expiry must not survive a valid signature: %v", e.expiredExp)
		}
		if !e.validExp.Equal(validExp) {
			t.Errorf("validExp = %v, want %v", e.validExp, validExp)
		}
	}

	t.Run("expired before valid counts as valid, not expired", func(t *testing.T) {
		assertValid(t, evalRRSIGCover([]dns.RR{expired, valid}, dns.TypeSOA, 111, now))
	})

	t.Run("valid before expired gives the same result", func(t *testing.T) {
		assertValid(t, evalRRSIGCover([]dns.RR{valid, expired}, dns.TypeSOA, 111, now))
	})

	t.Run("all expired still reports expired with the earliest expiry", func(t *testing.T) {
		older := mk(dns.TypeSOA, 111, now.Add(-2*time.Hour), now.Add(-48*time.Hour))
		e := evalRRSIGCover([]dns.RR{expired, older}, dns.TypeSOA, 111, now)
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
