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
