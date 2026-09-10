package config

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RDAYBLUEX-023: positive integer settings are converted to durations with
// overflow, positivity and operational-maximum checks, through both the file
// and the environment loaders, before any server or goroutine exists.

func TestRDAYBLUEX023_CheckedDuration(t *testing.T) {
	maxSec := int(math.MaxInt64 / int64(time.Second))
	cases := []struct {
		name string
		n    int
		unit time.Duration
		max  int
		want string // "" = ok
	}{
		{"ordinary", 30, time.Second, 600, ""},
		{"at max", 600, time.Second, 600, ""},
		{"max plus one", 601, time.Second, 600, "exceeds the maximum"},
		{"zero", 0, time.Second, 600, "must be positive"},
		{"negative", -1, time.Second, 600, "must be positive"},
		{"MaxInt64/unit (representable, above max)", maxSec, time.Second, 600, "exceeds the maximum"},
		{"MaxInt64/unit + 1 (overflow)", maxSec + 1, time.Second, math.MaxInt, "overflows"},
		{"MaxInt", math.MaxInt, time.Second, math.MaxInt, "overflows"},
		{"minutes overflow", int(math.MaxInt64/int64(time.Minute)) + 1, time.Minute, math.MaxInt, "overflows"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := checkedDuration("f", c.n, c.unit, c.max)
			if c.want == "" {
				if err != nil || d != time.Duration(c.n)*c.unit {
					t.Fatalf("expected %s, got %s / %v", time.Duration(c.n)*c.unit, d, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "f") {
				t.Fatalf("expected an error naming the field with %q, got %v", c.want, err)
			}
		})
	}
}

// Every converted field, through both loaders, at the overflow boundaries and
// at ordinary values.
func TestRDAYBLUEX023_LoadersRejectOverflowingDurations(t *testing.T) {
	maxSec := int(math.MaxInt64 / int64(time.Second))
	maxMin := int(math.MaxInt64 / int64(time.Minute))
	type field struct {
		toml, env string
		overflow  int
		max       int
	}
	fields := []field{
		{"query_timeout_seconds", "QUERY_TIMEOUT_SECONDS", maxSec + 1, MaxQueryTimeoutSec},
		{"total_timeout_seconds", "TOTAL_TIMEOUT_SECONDS", maxSec + 1, MaxTotalTimeoutSec},
		{"shutdown_timeout_seconds", "SHUTDOWN_TIMEOUT_SECONDS", maxSec + 1, MaxShutdownTimeoutSec},
		{"rate_limit.cleanup_seconds", "RATE_LIMIT_CLEANUP_SECONDS", maxSec + 1, MaxRateLimitCleanupSec},
	}
	writeTOML := func(t *testing.T, key string, v int) string {
		t.Helper()
		var body string
		if strings.HasPrefix(key, "rate_limit.") {
			body = fmt.Sprintf("[rate_limit]\n%s = %d\n", strings.TrimPrefix(key, "rate_limit."), v)
		} else {
			body = fmt.Sprintf("%s = %d\n", key, v)
		}
		p := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, f := range fields {
		for _, v := range []int{f.overflow, math.MaxInt, f.max + 1, -1, 0} {
			t.Run(fmt.Sprintf("file %s=%d", f.toml, v), func(t *testing.T) {
				if _, err := LoadFromFile(writeTOML(t, f.toml, v)); err == nil || !strings.Contains(err.Error(), f.toml) {
					t.Fatalf("value %d must be a load error naming %s, got %v", v, f.toml, err)
				}
			})
			t.Run(fmt.Sprintf("env %s=%d", f.env, v), func(t *testing.T) {
				t.Setenv(f.env, fmt.Sprint(v))
				if _, err := LoadFromEnv(); err == nil || !strings.Contains(err.Error(), f.toml) {
					t.Fatalf("value %d must be a load error naming %s, got %v", v, f.toml, err)
				}
			})
		}
		t.Run("file "+f.toml+" ordinary", func(t *testing.T) {
			if _, err := LoadFromFile(writeTOML(t, f.toml, f.max)); err != nil {
				t.Fatalf("the maximum itself must load: %v", err)
			}
		})
	}
	// The heartbeat interval, converted only when enabled.
	t.Setenv("HEARTBEAT_ENABLED", "true")
	t.Setenv("HEARTBEAT_API_KEY", "k")
	t.Setenv("HEARTBEAT_APP", "a")
	t.Setenv("HEARTBEAT_URL", "https://hb.example.invalid/")
	for _, v := range []int{maxMin + 1, math.MaxInt, MaxHeartbeatIntervalMinut + 1, 0} {
		t.Setenv("HEARTBEAT_INTERVAL_MINUTES", fmt.Sprint(v))
		if _, err := LoadFromEnv(); err == nil || !strings.Contains(err.Error(), "heartbeat.interval_minutes") {
			t.Fatalf("heartbeat interval %d must be a load error, got %v", v, err)
		}
	}
	t.Setenv("HEARTBEAT_INTERVAL_MINUTES", "5")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("an ordinary heartbeat interval loads: %v", err)
	}
	if cfg.HeartbeatInterval != 5*time.Minute || cfg.QueryTimeout != 5*time.Second || cfg.RateLimitCleanup != 5*time.Minute {
		t.Fatalf("derived durations must equal the integers: %+v", cfg)
	}
}
