package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// R-013: operational durations must be positive, or NewTicker panics / http
// clients get no timeout.
func TestConfigValidate_OperationalDurationsPositive(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"poll_interval zero", func(c *Config) { c.PollInterval = Duration{0} }, "poll_interval"},
		{"poll_interval negative", func(c *Config) { c.PollInterval = Duration{-5 * time.Minute} }, "poll_interval"},
		{"shutdown_timeout zero", func(c *Config) { c.Health.ShutdownTimeout = Duration{0} }, "shutdown_timeout"},
		{"validate.timeout zero", func(c *Config) { c.Validation.Timeout = Duration{0} }, "validate.timeout"},
		{"registrar timeout zero", func(c *Config) { c.Registrar.Dynadot.Timeout = Duration{0} }, "registrar.dynadot.timeout"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.mutate(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.want)
			}
		})
	}

	// Defaults are all positive and must pass.
	if err := DefaultConfig().Validate(); err != nil {
		t.Errorf("DefaultConfig should validate: %v", err)
	}
}

// R-014: rollover timings must be positive and switch < prepublish.
func TestConfigValidate_RolloverDurations(t *testing.T) {
	t.Run("switch >= prepublish rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DNSSEC.RolloverSwitch = Duration{14 * 24 * time.Hour}
		cfg.DNSSEC.RolloverPrepublish = Duration{7 * 24 * time.Hour}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "rollover_switch") {
			t.Fatalf("expected rollover_switch ordering error, got %v", err)
		}
		if !strings.Contains(err.Error(), "rollover_prepublish") {
			t.Errorf("error should name both keys, got: %v", err)
		}
	})
	t.Run("negative switch rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DNSSEC.RolloverSwitch = Duration{-24 * time.Hour}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for negative rollover_switch")
		}
	})
	t.Run("zero prepublish rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.DNSSEC.RolloverPrepublish = Duration{0}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error for zero rollover_prepublish")
		}
	})
	t.Run("defaults pass", func(t *testing.T) {
		if err := DefaultConfig().Validate(); err != nil {
			t.Errorf("defaults should pass: %v", err)
		}
	})
}

// R-014: the pre-publish Action message is built from the configured switch
// duration, not a hardcoded "7 days".
func TestHumanizeRolloverDelay(t *testing.T) {
	if got := humanizeRolloverDelay(7 * 24 * time.Hour); got != "7 day(s)" {
		t.Errorf("7d = %q, want \"7 day(s)\"", got)
	}
	if got := humanizeRolloverDelay(10 * 24 * time.Hour); got != "10 day(s)" {
		t.Errorf("10d = %q, want \"10 day(s)\"", got)
	}
	if got := humanizeRolloverDelay(1 * time.Second); got != "1s" {
		t.Errorf("1s = %q, want \"1s\"", got)
	}
}

// R-015: unknown/misspelled TOML keys are rejected instead of silently ignored.
func TestLoadConfig_StrictUnknownKey(t *testing.T) {
	dir := t.TempDir()

	valid := `output_dir = "/tmp/out"
data_dir = "/tmp/data"
`
	validPath := filepath.Join(dir, "valid.toml")
	if err := os.WriteFile(validPath, []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(validPath); err != nil {
		t.Fatalf("valid config should load: %v", err)
	}

	// A typo in the DNSSEC signature-validity key must be a load-time error, not
	// a silent revert to the default.
	typo := valid + "\n[dnssec]\nsignture_validity = \"14d\"\n"
	typoPath := filepath.Join(dir, "typo.toml")
	if err := os.WriteFile(typoPath, []byte(typo), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadConfig(typoPath)
	if err == nil {
		t.Fatal("expected error for unknown key signture_validity")
	}
	if !strings.Contains(err.Error(), "signture_validity") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

// R-016: digest_type at the [registrar] level is honored; misplacing it under
// [registrar.dynadot] (the doc bug) is now a strict-decode load error.
func TestLoadConfig_RegistrarDigestType(t *testing.T) {
	dir := t.TempDir()

	good := `output_dir = "/tmp/out"
data_dir = "/tmp/data"

[registrar]
digest_type = 4
`
	gp := filepath.Join(dir, "good.toml")
	if err := os.WriteFile(gp, []byte(good), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(gp)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Registrar.DigestType(); got != 4 {
		t.Errorf("DigestType() = %d, want 4", got)
	}

	// The old doc's placement under [registrar.dynadot] must now error, not
	// silently fall back to SHA-256.
	bad := `output_dir = "/tmp/out"
data_dir = "/tmp/data"

[registrar.dynadot]
digest_type = 4
`
	bp := filepath.Join(dir, "bad.toml")
	if err := os.WriteFile(bp, []byte(bad), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(bp); err == nil {
		t.Error("digest_type under [registrar.dynadot] should be rejected as an unknown key")
	}
}

// R-015: the shipped testdata config (every key maps to a struct tag) must keep
// loading under strict decoding.
func TestLoadConfig_TestdataStillLoads(t *testing.T) {
	if _, err := os.Stat("testdata/zones/example.com.zone"); err != nil {
		t.Skip("testdata zone file missing")
	}
	if _, err := LoadConfig("testdata/config.toml"); err != nil {
		t.Fatalf("testdata/config.toml must still load under strict decode: %v", err)
	}
}

// R-005: the --web loopback guard is enforced after the flag override.
func TestCheckWebFlagListen(t *testing.T) {
	t.Run("non-loopback --web rejected", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Web.Enabled = true
		cfg.Web.Listen = ":8053" // all interfaces
		if err := checkWebFlagListen(cfg); err == nil {
			t.Fatal("expected error binding the unauthenticated dashboard to all interfaces")
		}
	})
	t.Run("allow_remote permits non-loopback", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Web.Enabled = true
		cfg.Web.Listen = ":8053"
		cfg.Web.AllowRemote = true
		if err := checkWebFlagListen(cfg); err != nil {
			t.Errorf("allow_remote should permit non-loopback: %v", err)
		}
	})
	t.Run("loopback --web allowed", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Web.Enabled = true
		cfg.Web.Listen = "127.0.0.1:8053"
		if err := checkWebFlagListen(cfg); err != nil {
			t.Errorf("loopback listen should be allowed: %v", err)
		}
	})
	t.Run("web disabled skips check", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Web.Enabled = false
		cfg.Web.Listen = ":8053"
		if err := checkWebFlagListen(cfg); err != nil {
			t.Errorf("disabled web should skip the guard: %v", err)
		}
	})
}
