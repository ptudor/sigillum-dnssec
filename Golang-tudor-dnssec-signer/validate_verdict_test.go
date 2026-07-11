package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// mkDNSKEY builds a valid Ed25519 KSK DNSKEY for DS computation in tests.
func mkDNSKEY(t *testing.T, name string) *dns.DNSKEY {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
}

// R-045: a parent holding only the SHA-384 DS still matches (both digests are
// computed and either counts). R-046: during a rollover, the old KSK's DS is
// accepted. R-047: an unloadable local KSK does not fail open to "pass".
func TestEvaluateDSMatch(t *testing.T) {
	key := mkDNSKEY(t, "example.com.")
	ds384 := key.ToDS(dns.SHA384)
	if ds384 == nil {
		t.Fatal("ToDS(SHA384) returned nil")
	}

	t.Run("SHA-384 DS at parent matches (R-045)", func(t *testing.T) {
		r := evaluateDSMatch(DSCheckResult{}, []*dns.DS{ds384}, []*dns.DNSKEY{key}, false)
		if r.Status != "pass" || !r.MatchesKSK {
			t.Errorf("SHA-384 DS should match: status=%q matches=%v details=%q", r.Status, r.MatchesKSK, r.Details)
		}
	})

	t.Run("old KSK DS accepted during rollover (R-046)", func(t *testing.T) {
		oldKey := mkDNSKEY(t, "example.com.")
		newKey := mkDNSKEY(t, "example.com.")
		oldDS := oldKey.ToDS(dns.SHA256)
		// Parent still holds only the OLD KSK's DS; both are acceptable.
		r := evaluateDSMatch(DSCheckResult{}, []*dns.DS{oldDS}, []*dns.DNSKEY{newKey, oldKey}, false)
		if r.Status != "pass" || !r.MatchesKSK {
			t.Errorf("old KSK DS should match during rollover: status=%q details=%q", r.Status, r.Details)
		}
	})

	t.Run("unloadable local KSK does not fail open (R-047)", func(t *testing.T) {
		foreign := mkDNSKEY(t, "example.com.")
		foreignDS := foreign.ToDS(dns.SHA256)
		// DS exists at parent, but we have no loadable local KSK (it was expected).
		r := evaluateDSMatch(DSCheckResult{}, []*dns.DS{foreignDS}, nil, true)
		if r.Status == "pass" {
			t.Errorf("must not report pass when the local KSK is unloadable; got %q (%s)", r.Status, r.Details)
		}
		if r.Status != "error" {
			t.Errorf("expected error status, got %q", r.Status)
		}
	})

	t.Run("no DS at parent is fail", func(t *testing.T) {
		r := evaluateDSMatch(DSCheckResult{}, nil, []*dns.DNSKEY{key}, false)
		if r.Status != "fail" || r.Found {
			t.Errorf("no DS should be fail/not-found: status=%q found=%v", r.Status, r.Found)
		}
	})

	t.Run("non-matching DS is fail", func(t *testing.T) {
		foreign := mkDNSKEY(t, "example.com.")
		r := evaluateDSMatch(DSCheckResult{}, []*dns.DS{foreign.ToDS(dns.SHA256)}, []*dns.DNSKEY{key}, false)
		if r.Status != "fail" {
			t.Errorf("a DS that matches no acceptable KSK should be fail, got %q", r.Status)
		}
	})
}

// R-012: an expired RRSIG must never count as "signed"; a foreign-key RRSIG is
// ignored when the key tag is known.
func TestEvalRRSIGCover(t *testing.T) {
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

	t.Run("valid in-window RRSIG counts", func(t *testing.T) {
		ans := []dns.RR{mk(dns.TypeSOA, 111, now.Add(24*time.Hour), now.Add(-time.Hour))}
		e := evalRRSIGCover(ans, dns.TypeSOA, 111, now)
		if !e.valid || e.expired {
			t.Errorf("valid RRSIG: got valid=%v expired=%v", e.valid, e.expired)
		}
	})

	t.Run("expired RRSIG does not count as valid", func(t *testing.T) {
		ans := []dns.RR{mk(dns.TypeSOA, 111, now.Add(-time.Hour), now.Add(-48*time.Hour))}
		e := evalRRSIGCover(ans, dns.TypeSOA, 111, now)
		if e.valid {
			t.Error("expired RRSIG must not be valid")
		}
		if !e.present || !e.expired {
			t.Errorf("expired RRSIG should be present+expired: present=%v expired=%v", e.present, e.expired)
		}
	})

	t.Run("foreign key tag is ignored when tag is known", func(t *testing.T) {
		ans := []dns.RR{mk(dns.TypeSOA, 999, now.Add(24*time.Hour), now.Add(-time.Hour))}
		e := evalRRSIGCover(ans, dns.TypeSOA, 111, now) // want tag 111, record has 999
		if e.present || e.valid {
			t.Errorf("foreign-key RRSIG must not count: present=%v valid=%v", e.present, e.valid)
		}
	})

	t.Run("unknown local tag accepts any signer", func(t *testing.T) {
		ans := []dns.RR{mk(dns.TypeSOA, 999, now.Add(24*time.Hour), now.Add(-time.Hour))}
		e := evalRRSIGCover(ans, dns.TypeSOA, 0, now) // wantTag 0 = unknown
		if !e.valid {
			t.Error("with unknown local tag, an in-window RRSIG should count")
		}
	})
}

// R-048: DS-present with a failing DNSKEY/RRSIG is bogus (fail), not partial.
func TestBogusWhenDSPresent(t *testing.T) {
	cases := []struct {
		overall             string
		dsFound             bool
		dnskey, rrsig, want string
	}{
		{"partial", true, "fail", "pass", "fail"},
		{"partial", true, "pass", "fail", "fail"},
		{"partial", true, "pass", "pass", "partial"},
		{"pass", true, "pass", "pass", "pass"},
		{"partial", false, "fail", "fail", "partial"}, // no DS → not our concern
	}
	for _, c := range cases {
		got := bogusWhenDSPresent(c.overall, c.dsFound, c.dnskey, c.rrsig)
		if got != c.want {
			t.Errorf("bogusWhenDSPresent(%q,%v,%q,%q) = %q, want %q",
				c.overall, c.dsFound, c.dnskey, c.rrsig, got, c.want)
		}
	}
}
