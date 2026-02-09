package main

import (
	"strings"
	"testing"
)

func TestConfigValidate_DefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() failed: %v", err)
	}
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
