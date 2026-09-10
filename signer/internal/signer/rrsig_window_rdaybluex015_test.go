package signer

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
)

// RDAYBLUEX-015: post-sign verification requires every RRSIG to be currently
// valid and to carry exactly the intended window, and the persisted
// signatures_expire is the earliest expiration actually written.

// resignWindows rewrites every RRSIG's window with fn and re-signs it with
// the matching private key, so the signature is cryptographically valid and
// only its window is wrong.
func resignWindows(t *testing.T, s *Signer, keys *signingKeys, records []dns.RR, fn func(sig *dns.RRSIG)) []dns.RR {
	t.Helper()
	rrsets, _ := groupRRsets(records)
	privByTag := map[uint16][]byte{}
	keyByTag := map[uint16]*dns.DNSKEY{}
	for i, k := range keys.signingKSKs {
		privByTag[k.KeyTag()], keyByTag[k.KeyTag()] = keys.signingKSKPs[i], k
	}
	for i, k := range keys.signingZSKs {
		privByTag[k.KeyTag()], keyByTag[k.KeyTag()] = keys.signingZSKPs[i], k
	}
	out := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			out = append(out, rr)
			continue
		}
		cp := dns.Copy(sig).(*dns.RRSIG)
		fn(cp)
		cp.Signature = ""
		wire := canonicalRRset(rrsets[rrsetKey{canonicalName(cp.Hdr.Name), cp.TypeCovered}])
		if err := s.signRRSIG(cp, wire, keyByTag[cp.KeyTag], privByTag[cp.KeyTag]); err != nil {
			t.Fatalf("re-sign: %v", err)
		}
		out = append(out, cp)
	}
	return out
}

func TestRDAYBLUEX015_VerificationRejectsBadWindows(t *testing.T) {
	lab := newSourceLab(t)
	if err := lab.s.SignZone(lab.domain); err != nil {
		t.Fatalf("initial sign: %v", err)
	}
	before, err := os.ReadFile(lab.s.OutputPath(lab.domain))
	if err != nil {
		t.Fatal(err)
	}
	zs := lab.state.GetZone(lab.domain)
	keys, err := lab.s.loadKeysForSigning(lab.domain, NewKeyGenerator(lab.cfg), zs)
	if err != nil {
		t.Fatal(err)
	}
	validity := lab.cfg.DNSSEC.SignatureValidity.Duration
	now := time.Now().UTC()
	at := func(t time.Time) uint32 { return uint32(t.Unix()) }
	cases := []struct {
		name string
		fn   func(sig *dns.RRSIG)
		want string
	}{
		{"expired", func(sig *dns.RRSIG) {
			sig.Inception, sig.Expiration = at(now.Add(-3*time.Hour)), at(now.Add(-time.Hour))
		}, "not currently valid"},
		{"not yet valid", func(sig *dns.RRSIG) {
			sig.Inception, sig.Expiration = at(now.Add(time.Hour)), at(now.Add(2*time.Hour))
		}, "not currently valid"},
		{"wrapped", func(sig *dns.RRSIG) {
			sig.Inception = at(now.Add(-config.SignatureInceptionBackdate))
			sig.Expiration = sig.Inception - 1 // expiration "before" inception under serial arithmetic
		}, "not currently valid"},
		{"unexpectedly long", func(sig *dns.RRSIG) {
			sig.Inception, sig.Expiration = at(now.Add(-config.SignatureInceptionBackdate)), at(now.Add(validity+24*time.Hour))
		}, "unexpected validity window"},
		{"unexpectedly short", func(sig *dns.RRSIG) {
			sig.Inception, sig.Expiration = at(now.Add(-time.Second)), at(now.Add(time.Second))
		}, "unexpected validity window"},
		{"right length, shifted into the future", func(sig *dns.RRSIG) {
			sig.Inception = at(now.Add(-config.SignatureInceptionBackdate).Add(signingWindowTolerance + time.Hour))
			sig.Expiration = at(now.Add(validity).Add(signingWindowTolerance + time.Hour))
		}, "not currently valid"},
		{"right length, shifted into the past within validity", func(sig *dns.RRSIG) {
			// The window is valid now and has the right span for the 14 d
			// validity this case configures, but it was not produced for
			// this pass (shifted by twice the tolerance).
			shift := 2 * signingWindowTolerance
			sig.Inception = at(now.Add(-config.SignatureInceptionBackdate).Add(-shift))
			sig.Expiration = at(now.Add(14 * 24 * time.Hour).Add(-shift))
		}, "away from the intended"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "right length, shifted into the past within validity" {
				// Only meaningful when a shift can exceed the tolerance
				// without leaving the valid window.
				lab.cfg.DNSSEC.SignatureValidity = config.Duration{Duration: 14 * 24 * time.Hour}
				defer func() { lab.cfg.DNSSEC.SignatureValidity = config.Duration{Duration: validity} }()
			}
			lab.s.mutateBeforeVerify = func(records []dns.RR) []dns.RR { return resignWindows(t, lab.s, keys, records, c.fn) }
			defer func() { lab.s.mutateBeforeVerify = nil }()
			// Force a re-sign attempt.
			lab.state.Mutate(func() { zs.ForceResign = true })
			err := lab.s.SignZone(lab.domain)
			if err == nil || !strings.Contains(err.Error(), "post-sign verification failed") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a verification failure containing %q, got %v", c.want, err)
			}
			after, _ := os.ReadFile(lab.s.OutputPath(lab.domain))
			if string(after) != string(before) {
				t.Fatal("the previous signed output must be kept")
			}
		})
	}
	// Unmodified windows still verify, and the persisted expiration is the
	// earliest RRSIG expiration actually written.
	lab.s.mutateBeforeVerify = nil
	lab.state.Mutate(func() { zs.ForceResign = true })
	if err := lab.s.SignZone(lab.domain); err != nil {
		t.Fatalf("a correct window must verify: %v", err)
	}
	earliest := earliestPublishedExpiration(t, lab.s.OutputPath(lab.domain))
	if !zs.SignaturesExp.Equal(earliest) {
		t.Fatalf("signatures_expire %s must equal the earliest published RRSIG expiration %s", zs.SignaturesExp, earliest)
	}
	if zs.SignaturesExp.After(time.Now().Add(validity)) {
		t.Fatal("state must never claim validity beyond the published signatures")
	}
}

func earliestPublishedExpiration(t *testing.T, path string) time.Time {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var earliest time.Time
	zp := dns.NewZoneParser(f, "", path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if sig, isSig := rr.(*dns.RRSIG); isSig {
			exp := time.Unix(int64(sig.Expiration), 0).UTC()
			if earliest.IsZero() || exp.Before(earliest) {
				earliest = exp
			}
		}
	}
	if err := zp.Err(); err != nil {
		t.Fatal(err)
	}
	return earliest
}

func TestRDAYBLUEX015_SerialTimeHelpers(t *testing.T) {
	ref := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	if got := serialTime(uint32(ref.Add(time.Hour).Unix()), ref); !got.Equal(ref.Add(time.Hour)) {
		t.Fatalf("serialTime forward = %s", got)
	}
	if got := serialTime(uint32(ref.Add(-time.Hour).Unix()), ref); !got.Equal(ref.Add(-time.Hour)) {
		t.Fatalf("serialTime backward = %s", got)
	}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "a.", Rrtype: dns.TypeRRSIG}, TypeCovered: dns.TypeA, Expiration: uint32(ref.Add(2 * time.Hour).Unix())}
	if got := earliestRRSIGExpiration([]dns.RR{sig}); got.IsZero() {
		t.Fatal("an RRSIG yields an expiration")
	}
	if !earliestRRSIGExpiration(nil).IsZero() {
		t.Fatal("no RRSIG yields the zero time")
	}
}
