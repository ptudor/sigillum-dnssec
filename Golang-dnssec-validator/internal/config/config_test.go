package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigValidate_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() failed: %v", err)
	}
}

func TestGetEnvInt(t *testing.T) {
	const key = "DNSSEC_VALIDATOR_TEST_INT"

	t.Run("valid integer is parsed", func(t *testing.T) {
		t.Setenv(key, "42")
		if got := getEnvInt(key, 7); got != 42 {
			t.Fatalf("getEnvInt = %d, want 42", got)
		}
	})

	t.Run("malformed value falls back to default", func(t *testing.T) {
		// A Go-duration string like "5s" is not a valid integer; getEnvInt must
		// reject it (and log a warning) rather than parse it as a partial number.
		t.Setenv(key, "5s")
		if got := getEnvInt(key, 7); got != 7 {
			t.Fatalf("getEnvInt = %d, want default 7", got)
		}
	})

	t.Run("unset value uses default", func(t *testing.T) {
		if got := getEnvInt("DNSSEC_VALIDATOR_TEST_UNSET", 9); got != 9 {
			t.Fatalf("getEnvInt = %d, want default 9", got)
		}
	})
}

func TestConfigValidate_RateLimitCleanupMustBePositive(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimit.CleanupSec = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for non-positive rate_limit.cleanup_seconds")
	}
	if !strings.Contains(err.Error(), "rate_limit.cleanup_seconds") {
		t.Fatalf("Validate() error = %q, expected cleanup_seconds message", err.Error())
	}
}

func TestConfigValidate_HeartbeatIntervalWhenEnabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Heartbeat.Enabled = true
	cfg.Heartbeat.APIKey = "test-key"
	cfg.Heartbeat.App = "dnssec-validator"
	cfg.Heartbeat.IntervalMinutes = 0

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for heartbeat interval when enabled")
	}
	if !strings.Contains(err.Error(), "heartbeat.interval_minutes") {
		t.Fatalf("Validate() error = %q, expected heartbeat interval message", err.Error())
	}
}

func TestConfigValidate_HeartbeatIntervalCanBeZeroWhenDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Heartbeat.Enabled = false
	cfg.Heartbeat.IntervalMinutes = 0

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() should allow zero heartbeat interval when disabled: %v", err)
	}
}

func TestConfigValidate_TrustedProxyCIDRsRejectInvalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxyCIDRs = []string{"127.0.0.0/8", "not-a-cidr"}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for invalid trusted_proxy_cidrs entry")
	}
	if !strings.Contains(err.Error(), "trusted_proxy_cidrs") {
		t.Fatalf("Validate() error = %q, expected trusted_proxy_cidrs message", err.Error())
	}
}

func TestConfigValidate_TrustedProxyCIDRsAllowEmpty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxyCIDRs = []string{}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() should allow empty trusted_proxy_cidrs: %v", err)
	}
}

func TestConfigValidate_BasePath(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "empty allowed", value: "", wantErr: false},
		{name: "valid prefix", value: "/dnssec", wantErr: false},
		{name: "must start with slash", value: "dnssec", wantErr: true},
		{name: "must not be root", value: "/", wantErr: true},
		{name: "must not end slash", value: "/dnssec/", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.BasePath = tt.value
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("Validate() expected error for base_path=%q", tt.value)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() unexpected error for base_path=%q: %v", tt.value, err)
			}
		})
	}
}

func TestConfigValidate_MetricsAllowedCIDRsRejectInvalid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MetricsAllowedCIDRs = []string{"10.0.0.0/8", "bad-cidr"}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for invalid metrics_allowed_cidrs")
	}
	if !strings.Contains(err.Error(), "metrics_allowed_cidrs") {
		t.Fatalf("Validate() error = %q, expected metrics_allowed_cidrs message", err.Error())
	}
}

// TestDefaultConfig_MetricsLoopbackOnly (R-098): /metrics is loopback-only by
// default so Prometheus internals are not world-readable out of the box. An
// empty default would mean "no CIDR restriction" — the bug this fixes.
func TestDefaultConfig_MetricsLoopbackOnly(t *testing.T) {
	cfg := DefaultConfig()
	if len(cfg.MetricsAllowedCIDRs) == 0 {
		t.Fatal("default MetricsAllowedCIDRs must not be empty (empty = unrestricted)")
	}
	want := map[string]bool{"127.0.0.0/8": true, "::1/128": true}
	for _, c := range cfg.MetricsAllowedCIDRs {
		if !want[c] {
			t.Errorf("unexpected default metrics CIDR %q (default must be loopback-only)", c)
		}
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("default metrics CIDRs missing loopback entries: %v", want)
	}
}

// TestLoadFromFile_RejectsUnknownKey (R-093): strict TOML decoding turns a
// misspelled key into a load-time error instead of silently ignoring it.
func TestLoadFromFile_RejectsUnknownKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.toml")
	// `max_concurent` is a typo of `max_concurrent` (missing an 'r').
	content := "listen_addr = \":9999\"\nmax_concurent = 5\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromFile(path); err == nil {
		t.Fatal("expected error for unknown/misspelled key, got nil")
	} else if !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("error should name the unknown key, got: %v", err)
	}
}

// TestLoadFromFile_AcceptsKnownKeys (R-093): a config using only recognized keys
// still loads and applies, so strict decoding doesn't break valid files.
func TestLoadFromFile_AcceptsKnownKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.toml")
	content := "listen_addr = \":9999\"\nmax_concurrent = 7\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("valid config should load: %v", err)
	}
	if cfg.ListenAddr != ":9999" || cfg.MaxConcurrent != 7 {
		t.Errorf("config not applied: listen=%q max_concurrent=%d", cfg.ListenAddr, cfg.MaxConcurrent)
	}
}
