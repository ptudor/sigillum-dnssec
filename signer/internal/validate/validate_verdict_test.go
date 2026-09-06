package validate

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
	f := newSignedFixture(t, "example.com.", 256)
	keys := []*dns.DNSKEY{f.key}
	answer := func(sigs ...dns.RR) []dns.RR { return append(append([]dns.RR{}, f.soa...), sigs...) }

	t.Run("valid in-window verifying RRSIG counts", func(t *testing.T) {
		e := evalRRSIGCover(answer(f.sign(t, f.soa, now.Add(-time.Hour), now.Add(24*time.Hour))), dns.TypeSOA, keys, now)
		if !e.valid || e.expired || e.broken {
			t.Errorf("valid RRSIG: got valid=%v expired=%v broken=%v", e.valid, e.expired, e.broken)
		}
	})

	t.Run("expired RRSIG does not count as valid", func(t *testing.T) {
		e := evalRRSIGCover(answer(f.sign(t, f.soa, now.Add(-48*time.Hour), now.Add(-time.Hour))), dns.TypeSOA, keys, now)
		if e.valid {
			t.Error("expired RRSIG must not be valid")
		}
		if !e.present || !e.expired {
			t.Errorf("expired RRSIG should be present+expired: present=%v expired=%v", e.present, e.expired)
		}
	})

	t.Run("corrupt signature bytes are broken, not valid", func(t *testing.T) {
		sig := f.sign(t, f.soa, now.Add(-time.Hour), now.Add(24*time.Hour))
		b := []byte(sig.Signature)
		if b[0] == 'A' {
			b[0] = 'B'
		} else {
			b[0] = 'A'
		}
		sig.Signature = string(b)
		e := evalRRSIGCover(answer(sig), dns.TypeSOA, keys, now)
		if e.valid || !e.present || !e.broken {
			t.Errorf("corrupt RRSIG must be present+broken: present=%v valid=%v broken=%v", e.present, e.valid, e.broken)
		}
	})

	t.Run("empty signature is broken", func(t *testing.T) {
		sig := f.sign(t, f.soa, now.Add(-time.Hour), now.Add(24*time.Hour))
		sig.Signature = ""
		e := evalRRSIGCover(answer(sig), dns.TypeSOA, keys, now)
		if e.valid || !e.broken {
			t.Errorf("empty RRSIG must not be valid: valid=%v broken=%v", e.valid, e.broken)
		}
	})

	t.Run("signature over a different RRset does not verify", func(t *testing.T) {
		other := newSignedFixture(t, "example.com.", 256)
		other.soa[0].(*dns.SOA).Serial = 99 // same owner/type, different data
		sig := f.sign(t, other.soa, now.Add(-time.Hour), now.Add(24*time.Hour))
		e := evalRRSIGCover(answer(sig), dns.TypeSOA, keys, now)
		if e.valid || !e.broken {
			t.Errorf("a signature over other data must be broken: valid=%v broken=%v", e.valid, e.broken)
		}
	})

	t.Run("foreign key is ignored", func(t *testing.T) {
		foreign := newSignedFixture(t, "example.com.", 256)
		sig := foreign.sign(t, f.soa, now.Add(-time.Hour), now.Add(24*time.Hour))
		e := evalRRSIGCover(answer(sig), dns.TypeSOA, keys, now)
		if e.present || e.valid {
			t.Errorf("foreign-key RRSIG must not count: present=%v valid=%v", e.present, e.valid)
		}
	})

	t.Run("same tag, different key material is not our key", func(t *testing.T) {
		// A served key that merely shares the tag: verification against OUR
		// material fails, so the signature is broken rather than accepted.
		impostor := newSignedFixture(t, "example.com.", 256)
		sig := impostor.sign(t, f.soa, now.Add(-time.Hour), now.Add(24*time.Hour))
		sig.KeyTag = f.key.KeyTag()
		e := evalRRSIGCover(answer(sig), dns.TypeSOA, keys, now)
		if e.valid || !e.broken {
			t.Errorf("tag-only match must not validate: valid=%v broken=%v", e.valid, e.broken)
		}
	})

	t.Run("wrong owner or signer name is not this RRset's signature", func(t *testing.T) {
		sig := f.sign(t, f.soa, now.Add(-time.Hour), now.Add(24*time.Hour))
		sig.Hdr.Name = "other.example."
		e := evalRRSIGCover(answer(sig), dns.TypeSOA, keys, now)
		if e.present || e.valid {
			t.Errorf("owner-mismatched RRSIG must not count: present=%v valid=%v", e.present, e.valid)
		}
		sig2 := f.sign(t, f.soa, now.Add(-time.Hour), now.Add(24*time.Hour))
		sig2.SignerName = "other.example."
		e = evalRRSIGCover(answer(sig2), dns.TypeSOA, keys, now)
		if e.present || e.valid {
			t.Errorf("signer-mismatched RRSIG must not count: present=%v valid=%v", e.present, e.valid)
		}
	})
}

// R-048: DS-present with a failing DNSKEY/RRSIG is bogus (fail), not partial.
func TestBogusWhenDSPresent(t *testing.T) {
	ds := func(found, matches bool, status string) DSCheckResult {
		return DSCheckResult{Found: found, MatchesKSK: matches, Status: status}
	}
	cases := []struct {
		name   string
		ds     DSCheckResult
		dnskey string
		rrsig  RRSIGCheckResult
		want   bool
	}{
		{"DNSKEY fails under a DS", ds(true, true, "pass"), "fail", RRSIGCheckResult{Status: "pass"}, true},
		{"RRSIG fails under a DS", ds(true, true, "pass"), "pass", RRSIGCheckResult{Status: "fail", Broken: true}, true},
		{"refresh-window partial stays partial", ds(true, true, "pass"), "pass", RRSIGCheckResult{Status: "partial"}, false},
		{"one required signature missing is bogus (RA6X-032)", ds(true, true, "pass"), "pass", RRSIGCheckResult{Status: "partial", Broken: true}, true},
		{"mismatching parent DS is bogus (RA6X-032)", ds(true, false, "fail"), "pass", RRSIGCheckResult{Status: "pass"}, true},
		{"all pass", ds(true, true, "pass"), "pass", RRSIGCheckResult{Status: "pass"}, false},
		{"no DS → not our concern", ds(false, false, "fail"), "fail", RRSIGCheckResult{Status: "fail", Broken: true}, false},
		{"DS check errored (uncertain)", DSCheckResult{Found: true, Status: "error"}, "pass", RRSIGCheckResult{Status: "pass"}, false},
	}
	for _, c := range cases {
		got := bogusWhenDSPresent(c.ds, DNSKEYCheckResult{Status: c.dnskey}, c.rrsig)
		if got != c.want {
			t.Errorf("%s: bogusWhenDSPresent = %v, want %v", c.name, got, c.want)
		}
	}
}
