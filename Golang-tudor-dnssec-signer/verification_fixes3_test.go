package main

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- Item 7: a panic in dashboard validation must not kill the daemon ---

// The validation-cache compute goroutine (web.go) runs outside net/http's
// per-request panic recovery, so a panic in ValidateAll would crash the whole
// daemon pre-fix. The recover must also perform the goroutine's cleanup:
// waiters unblock instead of hanging, and inflight is cleared so a later get
// starts a fresh compute.
func TestValidationCache_ComputeRecoversFromPanic(t *testing.T) {
	c := &validationCache{}
	var calls int32
	panicking := func() *ValidateOutput {
		atomic.AddInt32(&calls, 1)
		panic("live-DNS validation exploded")
	}

	// (a) The process survives: an unrecovered panic in the compute goroutine
	// would kill the whole test binary. (b) The waiter unblocks promptly with
	// the nil cold-cache fallback — like the timeout path — rather than
	// hanging on a done channel that never closes or caching a result.
	start := time.Now()
	if got := c.get(panicking, time.Minute, 5*time.Second); got != nil {
		t.Errorf("panicking compute must not cache a result, got %+v", got)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("waiter did not unblock promptly after the panic: %v", el)
	}

	// (c) inflight was cleared, so a subsequent get starts a fresh compute
	// and serves its result.
	healthy := func() *ValidateOutput {
		atomic.AddInt32(&calls, 1)
		return &ValidateOutput{Zones: map[string]*ValidationResult{}}
	}
	if got := c.get(healthy, time.Minute, 5*time.Second); got == nil {
		t.Fatal("get after the panic returned nil — inflight was not cleared for a fresh compute")
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("expected the panicking compute and one fresh compute (2 calls), got %d", n)
	}
}

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

// --- Item 12: post-sign verify gate must accept mixed-case duplicate owner spellings ---

// signMixedCaseZone mirrors signValidZone (post_sign_verify_test.go) but spells
// one RRset's owner with divergent letter case: `www` and `WWW` A records.
// DNSSEC canonical form (RFC 4034 §6.2) lowercases owner names, so these are
// one RRset on the wire and the signature over them is valid.
func signMixedCaseZone(t *testing.T) (*Signer, []dns.RR, *signingKeys) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	cfg.DNSSEC.NSECVersion = "nsec"
	keyGen := NewKeyGenerator(cfg)
	if _, err := keyGen.GenerateKSK("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := keyGen.GenerateZSK("example.com"); err != nil {
		t.Fatal(err)
	}
	kskKey, kskPriv, err := keyGen.LoadKeyPair("example.com", "ksk")
	if err != nil {
		t.Fatal(err)
	}
	zskKey, zskPriv, err := keyGen.LoadKeyPair("example.com", "zsk")
	if err != nil {
		t.Fatal(err)
	}
	keys := &signingKeys{
		dnskeys:      []*dns.DNSKEY{kskKey, zskKey},
		signingKSKs:  []*dns.DNSKEY{kskKey},
		signingKSKPs: [][]byte{kskPriv},
		signingZSKs:  []*dns.DNSKEY{zskKey},
		signingZSKPs: [][]byte{zskPriv},
	}

	mk := func(s string) dns.RR {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return rr
	}
	records := []dns.RR{
		mk("example.com. 3600 IN SOA ns.example.com. admin.example.com. 1 3600 600 86400 3600"),
		mk("example.com. 3600 IN NS ns.example.com."),
		mk("www.example.com. 3600 IN A 192.0.2.1"),
		mk("WWW.example.com. 3600 IN A 192.0.2.2"),
	}
	for _, k := range keys.dnskeys {
		records = append(records, k)
	}
	s := NewSigner(cfg, nil)
	records = append(records, s.generateNSECChain("example.com", records, 3600)...)

	signed, err := s.signRecordsWithKeys("example.com", records, keys)
	if err != nil {
		t.Fatalf("signRecordsWithKeys: %v", err)
	}
	return s, signed, keys
}

// A zone spelling one owner in different letter case within an RRset signs
// fine and validates on the wire; the verify gate must not reject it
// (pre-fix, miekg's case-sensitive IsRRset made sig.Verify return ErrRRset).
// The gate must not go blind either: a genuinely corrupt RRSIG over the
// mixed-case RRset is still rejected.
func TestVerifySignedZone_MixedCaseOwnerRRset(t *testing.T) {
	t.Run("mixed-case owner spellings pass verification", func(t *testing.T) {
		s, signed, keys := signMixedCaseZone(t)
		if err := s.verifySignedZone("example.com", signed, keys); err != nil {
			t.Fatalf("a signed zone with mixed-case owner spellings must pass verification, got: %v", err)
		}
		// Verification works on copies: the records that will be written keep
		// their original spelling.
		foundUpper := false
		for _, rr := range signed {
			if rr.Header().Rrtype == dns.TypeA && strings.HasPrefix(rr.Header().Name, "WWW.") {
				foundUpper = true
				break
			}
		}
		if !foundUpper {
			t.Error("verification must not mutate the records to be written (WWW. spelling lost)")
		}
	})

	t.Run("corrupt RRSIG over the mixed-case RRset is still rejected", func(t *testing.T) {
		s, signed, keys := signMixedCaseZone(t)
		corrupted := false
		for _, rr := range signed {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA {
				// Flip a byte of the base64 signature so it no longer verifies.
				b := []byte(sig.Signature)
				if b[0] == 'A' {
					b[0] = 'B'
				} else {
					b[0] = 'A'
				}
				sig.Signature = string(b)
				corrupted = true
				break
			}
		}
		if !corrupted {
			t.Fatal("no A RRSIG found to corrupt")
		}
		if err := s.verifySignedZone("example.com", signed, keys); err == nil {
			t.Fatal("a corrupt RRSIG over a mixed-case RRset must still fail verification")
		}
	})
}
