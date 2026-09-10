package config

import (
	"math"
	"strings"
	"testing"
	"time"
)

// RDAYBLUEX-024: parent_ds_ttl is validated as an exact whole-second value in
// policy before any rollover begins, and the single checked conversion can
// neither truncate to zero nor wrap.

func TestRDAYBLUEX024_ValidateParentDSTTL(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
		want string // substring of the error, "" for accepted
	}{
		{"unset", 0, ""},
		{"500ms truncates to zero", 500 * time.Millisecond, "at least"},
		{"999ms", 999 * time.Millisecond, "at least"},
		{"1s", time.Second, ""},
		{"1.5s fractional", 1500 * time.Millisecond, "whole number of seconds"},
		{"24h", 24 * time.Hour, ""},
		{"7d maximum", 7 * 24 * time.Hour, ""},
		{"7d+1s", 7*24*time.Hour + time.Second, "at most"},
		{"MaxUint32 seconds", time.Duration(math.MaxUint32) * time.Second, "at most"},
		{"MaxUint32+1 seconds (would wrap)", time.Duration(math.MaxUint32+1) * time.Second, "at most"},
		{"negative", -time.Second, "negative"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateParentDSTTL(c.d)
			if c.want == "" {
				if err != nil {
					t.Fatalf("%s must be accepted, got %v", c.d, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%s must be rejected with %q, got %v", c.d, c.want, err)
			}
		})
	}
}

// Config.Validate applies the same rule, and the checked fallback never
// yields zero or a wrapped value even when validation was bypassed.
func TestRDAYBLUEX024_ConfigValidateAndCheckedFallback(t *testing.T) {
	base := func() *Config {
		c := DefaultConfig()
		c.OutputDir, c.DataDir = "/tmp/out", "/tmp/data"
		return c
	}
	for _, d := range []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond, 8 * 24 * time.Hour, time.Duration(math.MaxUint32+1) * time.Second} {
		c := base()
		c.DNSSEC.ParentDSTTL = Duration{Duration: d}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "parent_ds_ttl") {
			t.Fatalf("parent_ds_ttl %s must fail validation, got %v", d, err)
		}
		// Bypassing validation: the fallback is the conservative default, not
		// a truncated or wrapped value.
		if got := c.ParentDSTTLFallbackSeconds(); got != 86400 {
			t.Fatalf("out-of-policy %s must fall back to 24h (86400 s), got %d", d, got)
		}
	}
	for _, d := range []time.Duration{0, time.Second, 90 * time.Minute, 24 * time.Hour, 7 * 24 * time.Hour} {
		c := base()
		c.DNSSEC.ParentDSTTL = Duration{Duration: d}
		if err := c.Validate(); err != nil {
			t.Fatalf("parent_ds_ttl %s must validate: %v", d, err)
		}
		want := uint32(d / time.Second)
		if d == 0 {
			want = 86400
		}
		if got := c.ParentDSTTLFallbackSeconds(); got != want {
			t.Fatalf("fallback seconds for %s: got %d want %d", d, got, want)
		}
	}
}
