package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RDAYBLUEX-015 / RDAYBLUEX-021: signature validity is representable and
// bounded, and the refresh window covers the poll interval with an allowance
// for a signing pass. RDAYBLUEX-030: per-zone lifetime overrides may inherit
// (omitted or zero) or override (positive), never be negative.

func TestRDAYBLUEX015_021_SignatureTiming(t *testing.T) {
	const day = 24 * time.Hour
	poll := 5 * time.Minute
	cases := []struct {
		name              string
		validity, refresh time.Duration
		poll              time.Duration
		want              string
	}{
		{"defaults", 14 * day, 3 * day, poll, ""},
		{"one year maximum", 366 * day, 3 * day, poll, ""},
		{"one year plus a day", 367 * day, 3 * day, poll, "at most"},
		{"100 years", 100 * 365 * day, 3 * day, poll, "not representable"},
		{"exact serial boundary 2^31 s", time.Duration(1<<31) * time.Second, 3 * day, poll, "not representable"},
		{"just under the boundary but with the backdate over it", time.Duration(1<<31-1800) * time.Second, 3 * day, poll, "not representable"},
		{"just under the boundary and the maximum", time.Duration(1<<31-7200) * time.Second, 3 * day, poll, "at most"},
		{"validity below the minimum", 30 * time.Minute, time.Minute, time.Second, "at least 1h"},
		{"refresh below the minimum", 2 * time.Hour, 30 * time.Second, time.Second, "at least 1m"},
		{"sub-second pair", 500 * time.Millisecond, 100 * time.Millisecond, time.Second, "at least 1h"},
		{"refresh equal to validity", 2 * time.Hour, 2 * time.Hour, poll, "less than"},
		{"refresh above validity", 2 * time.Hour, 3 * time.Hour, poll, "less than"},
		{"refresh just below the required margin", 14 * day, 2*poll - time.Second, poll, "poll_interval"},
		{"refresh equal to the required margin", 14 * day, 2 * poll, poll, ""},
		{"refresh just above the required margin", 14 * day, 2*poll + time.Second, poll, ""},
		{"refresh equal to poll (below the allowance)", 14 * day, poll, poll, "poll_interval"},
		{"multi-zone worst case: 1h poll needs a 2h refresh", 14 * day, 90 * time.Minute, time.Hour, "poll_interval"},
		{"multi-zone worst case satisfied", 14 * day, 2 * time.Hour, time.Hour, ""},
		{"zero validity", 0, time.Minute, poll, "positive"},
		{"negative refresh", 2 * time.Hour, -time.Minute, poll, "positive"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateSignatureTiming(c.validity, c.refresh, c.poll)
			if c.want == "" {
				if err != nil {
					t.Fatalf("must be accepted: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %v", c.want, err)
			}
		})
	}

	// Config.Validate applies the rule.
	c := DefaultConfig()
	c.OutputDir, c.DataDir = "/tmp/out", "/tmp/data"
	if err := c.Validate(); err != nil {
		t.Fatalf("defaults validate: %v", err)
	}
	c.DNSSEC.SignatureRefresh = Duration{Duration: 9 * time.Minute}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "poll_interval") {
		t.Fatalf("a refresh window shorter than two poll intervals must fail: %v", err)
	}
	c.DNSSEC.SignatureRefresh = Duration{Duration: 3 * day}
	c.DNSSEC.SignatureValidity = Duration{Duration: 100 * 365 * day}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "not representable") {
		t.Fatalf("a 100 year validity must fail: %v", err)
	}
}

func TestRDAYBLUEX030_PerZoneLifetimes(t *testing.T) {
	dir := t.TempDir()
	zone := filepath.Join(dir, "zone.db")
	if err := os.WriteFile(zone, []byte("$ORIGIN example.test.\n@ 3600 IN SOA ns1 admin 1 3600 1800 604800 86400\n@ 3600 IN NS ns1\nns1 3600 IN A 192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := "output_dir = \"" + filepath.Join(dir, "signed") + "\"\ndata_dir = \"" + dir + "\"\n"
	load := func(t *testing.T, zoneLines string) (*Config, error) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "config.toml")
		body := base + "\n[zones.\"example.test\"]\npath = \"" + zone + "\"\n" + zoneLines
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig(p)
	}
	cases := []struct {
		name  string
		lines string
		want  string // error substring, "" for accepted
		ksk   time.Duration
		zsk   time.Duration
	}{
		{"omitted inherits", "", "", 5 * 365 * 24 * time.Hour, 90 * 24 * time.Hour},
		{"zero inherits", "ksk_lifetime = \"0s\"\nzsk_lifetime = \"0s\"\n", "", 5 * 365 * 24 * time.Hour, 90 * 24 * time.Hour},
		{"positive overrides", "ksk_lifetime = \"2y\"\nzsk_lifetime = \"30d\"\n", "", 2 * 365 * 24 * time.Hour, 30 * 24 * time.Hour},
		{"negative ksk", "ksk_lifetime = \"-1d\"\n", "zone \"example.test\": ksk_lifetime must not be negative", 0, 0},
		{"negative zsk", "zsk_lifetime = \"-30d\"\n", "zone \"example.test\": zsk_lifetime must not be negative", 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := load(t, c.lines)
			if c.want != "" {
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("want a load error containing %q, got %v", c.want, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("must load: %v", err)
			}
			if got := cfg.GetZoneKSKLifetime("example.test"); got != c.ksk {
				t.Fatalf("KSK lifetime %s, want %s", got, c.ksk)
			}
			if got := cfg.GetZoneZSKLifetime("example.test"); got != c.zsk {
				t.Fatalf("ZSK lifetime %s, want %s", got, c.zsk)
			}
		})
	}

	// A config edit keeps a valid file loadable, and a file holding a negative
	// override is refused by the loader the daemon's reload path uses, so it
	// can never replace a live snapshot.
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(base+"\n[zones.\"example.test\"]\npath = \""+zone+"\"\nksk_lifetime = \"2y\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.db")
	if err := os.WriteFile(other, []byte("$ORIGIN other.test.\n@ 3600 IN SOA ns1 admin 1 3600 1800 604800 86400\n@ 3600 IN NS ns1\nns1 3600 IN A 192.0.2.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := AddZoneToConfigFile(p, "other.test", other); err != nil {
		t.Fatalf("editing a valid file: %v", err)
	}
	cfg, err := LoadConfig(p)
	if err != nil || cfg.GetZoneKSKLifetime("example.test") != 2*365*24*time.Hour || cfg.GetZoneKSKLifetime("other.test") != 5*365*24*time.Hour {
		t.Fatalf("after the edit: %v %+v", err, cfg)
	}
	if err := os.WriteFile(p, []byte(base+"\n[zones.\"example.test\"]\npath = \""+zone+"\"\nzsk_lifetime = \"-1d\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err == nil || !strings.Contains(err.Error(), "zsk_lifetime must not be negative") {
		t.Fatalf("the reload loader must refuse the file: %v", err)
	}
}
