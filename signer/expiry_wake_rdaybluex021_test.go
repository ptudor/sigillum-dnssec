//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-021: the signing loop wakes at the earliest refresh threshold
// rather than relying on the poll ticker alone, and processes zones in
// expiration order, so signatures are refreshed before they expire even with
// a long poll interval and a slow zone ahead in the pass.

func rdaybluex021Daemon(t *testing.T, validity, refresh time.Duration, domains ...string) (*Daemon, *config.Config, *statepkg.State) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	cfg.LoadedAt = time.Now().UTC()
	cfg.PollInterval = config.Duration{Duration: time.Hour} // the ticker never fires in this test
	cfg.DNSSEC.SignatureValidity = config.Duration{Duration: validity}
	cfg.DNSSEC.SignatureRefresh = config.Duration{Duration: refresh}
	for _, d := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := signerpkg.EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	state := statepkg.NewState(cfg.StatePath())
	keyGen := signerpkg.NewKeyGenerator(cfg)
	for _, domain := range domains {
		path := filepath.Join(dataDir, domain+"zone")
		zone := "$ORIGIN " + domain + "\n$TTL 3600\n@\tIN\tSOA\tns1." + domain + " admin." + domain + " 2024011501 3600 1800 604800 86400\n@\tIN\tNS\tns1." + domain + "\nns1\tIN\tA\t192.0.2.1\n"
		if err := os.WriteFile(path, []byte(zone), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg.Zones[domain] = config.ZoneConfig{Path: path}
		ksk, err := keyGen.GenerateKSK(domain)
		if err != nil {
			t.Fatal(err)
		}
		zsk, err := keyGen.GenerateZSK(domain)
		if err != nil {
			t.Fatal(err)
		}
		state.SetZone(domain, &statepkg.ZoneState{Path: path, KSK: ksk, ZSK: zsk})
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	return NewDaemon(cfg, state), cfg, state
}

func waitSigned(t *testing.T, state *statepkg.State, domain string, after time.Time, within time.Duration) time.Time {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if zs := state.GetZoneCopy(domain); zs != nil && zs.LastSigned.After(after) {
			return zs.LastSigned
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s was not signed within %s", domain, within)
	return time.Time{}
}

func TestRDAYBLUEX021_RefreshWakeSignsBeforeExpiry(t *testing.T) {
	d, _, state := rdaybluex021Daemon(t, 6*time.Second, 3*time.Second, "wake.example.")
	d.markReady()
	d.wg.Add(1)
	go d.runSigningLoop()
	defer func() { d.cancel(); d.wg.Wait() }()

	first := waitSigned(t, state, "wake.example.", time.Time{}, 5*time.Second)
	firstExp := state.GetZoneCopy("wake.example.").SignaturesExp
	if firstExp.IsZero() {
		t.Fatal("expiration recorded")
	}
	// No poll tick can arrive (1h); the wake-up at expiration − refresh must
	// drive the re-sign, before the signatures expire.
	second := waitSigned(t, state, "wake.example.", first, time.Until(firstExp)+time.Second)
	if !second.Before(firstExp) {
		t.Fatalf("re-signed at %s, after the previous expiration %s", second, firstExp)
	}
	if second.Sub(first) < 2*time.Second {
		t.Fatalf("re-signed too early (%s after the first sign); the refresh threshold is 3 s before expiry", second.Sub(first))
	}
}

func TestRDAYBLUEX021_SlowEarlierZoneDoesNotExpireLaterOne(t *testing.T) {
	// "aaa" would come first alphabetically and is slow; "zzz" expires first
	// because it was signed first and must not be pushed past its expiry.
	d, _, state := rdaybluex021Daemon(t, 8*time.Second, 4*time.Second, "aaa.example.", "zzz.example.")
	// Initial pass: sign zzz first so it expires first.
	d.signAllZones()
	for _, domain := range []string{"aaa.example.", "zzz.example."} {
		if zs := state.GetZone(domain); zs == nil || zs.LastSigned.IsZero() {
			t.Fatalf("%s must be signed by the initial pass", domain)
		}
	}
	// Make zzz the most urgent by moving its recorded expiration earlier.
	zzz := state.GetZone("zzz.example.")
	state.Mutate(func() { zzz.SignaturesExp = zzz.SignaturesExp.Add(-2 * time.Second) })
	var slowCalls atomic.Int32
	beforeSignZone = func(domain string) {
		if domain == "aaa.example." {
			slowCalls.Add(1)
			time.Sleep(1500 * time.Millisecond)
		}
	}
	defer func() { beforeSignZone = nil }()

	zzzFirst := zzz.LastSigned
	zzzExp := zzz.SignaturesExp
	aaa := state.GetZoneCopy("aaa.example.")
	aaaFirst, aaaExp := aaa.LastSigned, aaa.SignaturesExp

	d.markReady()
	d.wg.Add(1)
	go d.runSigningLoop()
	defer func() { d.cancel(); d.wg.Wait() }()

	zzzSecond := waitSigned(t, state, "zzz.example.", zzzFirst, time.Until(zzzExp)+time.Second)
	if !zzzSecond.Before(zzzExp) {
		t.Fatalf("zzz re-signed at %s, after its expiration %s", zzzSecond, zzzExp)
	}
	aaaSecond := waitSigned(t, state, "aaa.example.", aaaFirst, time.Until(aaaExp)+time.Second)
	if !aaaSecond.Before(aaaExp) {
		t.Fatalf("aaa re-signed at %s, after its expiration %s", aaaSecond, aaaExp)
	}
	if !zzzSecond.Before(aaaSecond) {
		t.Fatalf("the zone expiring first must be processed first: zzz %s, aaa %s", zzzSecond, aaaSecond)
	}
	if slowCalls.Load() == 0 {
		t.Fatal("the slow seam must have run")
	}
}

func TestRDAYBLUEX021_UrgencyOrderAndNextDue(t *testing.T) {
	cfg := &config.Config{Zones: map[string]config.ZoneConfig{"a.": {}, "b.": {}, "c.": {}, "d.": {}}}
	cfg.DNSSEC.SignatureRefresh = config.Duration{Duration: time.Hour}
	state := statepkg.NewState("")
	now := time.Now()
	state.SetZone("a.", &statepkg.ZoneState{SignaturesExp: now.Add(3 * time.Hour)})
	state.SetZone("b.", &statepkg.ZoneState{SignaturesExp: now.Add(2 * time.Hour)})
	state.SetZone("c.", &statepkg.ZoneState{}) // never signed
	// d. has no state at all
	got := zonesByUrgency(cfg, state)
	if len(got) != 4 || got[0] != "c." || got[1] != "d." || got[2] != "b." || got[3] != "a." {
		t.Fatalf("urgency order = %v", got)
	}
	due := nextRefreshDue(cfg, state, now)
	if want := now.Add(time.Hour); !due.Equal(want) {
		t.Fatalf("next due %s, want %s (b. expiry − refresh)", due, want)
	}
	// A threshold already in the past is not scheduled.
	state.SetZone("b.", &statepkg.ZoneState{SignaturesExp: now.Add(30 * time.Minute)})
	if due := nextRefreshDue(cfg, state, now); !due.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("past thresholds are skipped: %s", due)
	}
	cfg.Zones = map[string]config.ZoneConfig{"c.": {}}
	if !nextRefreshDue(cfg, state, now).IsZero() {
		t.Fatal("no future threshold yields the zero time")
	}
}
