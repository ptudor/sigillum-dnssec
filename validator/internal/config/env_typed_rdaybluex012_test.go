package config

import (
	"math"
	"strconv"
	"strings"
	"testing"
)

// RDAYBLUEX-012: a present but malformed typed environment value is a load
// error naming the variable, never a silent default; absent and empty
// variables keep their defaults; every accepted boolean spelling still works.

func TestRDAYBLUEX012_TypedEnvironmentParsing(t *testing.T) {
	intVars := []string{
		"MAX_CONCURRENT", "MAX_CONCURRENT_VALIDATIONS",
		"RATE_LIMIT_PER_SEC", "RATE_LIMIT_BURST", "RATE_LIMIT_CLEANUP_SECONDS",
		"QUERY_TIMEOUT_SECONDS", "TOTAL_TIMEOUT_SECONDS", "SHUTDOWN_TIMEOUT_SECONDS",
		"HEARTBEAT_INTERVAL_MINUTES",
	}
	malformed := map[string]string{
		"duration suffix":    "5s",
		"decimal":            "1.5",
		"letters":            "ten",
		"whitespace only":    "   ",
		"overflow":           strconv.FormatUint(math.MaxUint64, 10) + "0",
		"negative sign only": "-",
		"embedded space":     "1 0",
	}
	for _, v := range intVars {
		for name, val := range malformed {
			t.Run(v+"/"+name, func(t *testing.T) {
				t.Setenv(v, val)
				_, err := LoadFromEnv()
				if err == nil {
					t.Fatalf("%s=%q must fail startup rather than use the default", v, val)
				}
				if !strings.Contains(err.Error(), v) {
					t.Fatalf("the error must name the variable %s: %v", v, err)
				}
				if strings.Contains(err.Error(), val) && strings.TrimSpace(val) != "" {
					t.Fatalf("the error must not echo the value: %v", err)
				}
			})
		}
		t.Run(v+"/surrounding whitespace is accepted", func(t *testing.T) {
			t.Setenv(v, " 7 ")
			cfg, err := LoadFromEnv()
			if err != nil {
				t.Fatalf("a padded integer loads: %v", err)
			}
			if v == "MAX_CONCURRENT" && cfg.MaxConcurrent != 7 {
				t.Fatalf("MAX_CONCURRENT = %d", cfg.MaxConcurrent)
			}
		})
	}

	// Absent and empty values keep their defaults.
	def := DefaultConfig()
	for _, v := range intVars {
		t.Setenv(v, "")
	}
	t.Setenv("HEARTBEAT_ENABLED", "")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("empty variables load with defaults: %v", err)
	}
	if cfg.MaxConcurrent != def.MaxConcurrent || cfg.RateLimit.Burst != def.RateLimit.Burst ||
		cfg.QueryTimeoutSec != def.QueryTimeoutSec || cfg.ShutdownTimeoutSec != def.ShutdownTimeoutSec ||
		cfg.Heartbeat.IntervalMinutes != def.Heartbeat.IntervalMinutes || cfg.Heartbeat.Enabled != def.Heartbeat.Enabled {
		t.Fatalf("defaults must apply to empty variables: %+v", cfg)
	}

	// Every accepted boolean spelling, and rejection of the rest.
	accepted := map[string]bool{
		"true": true, "TRUE": true, "True": true, "1": true, "yes": true, "YES": true, "on": true, "On": true,
		"false": false, "FALSE": false, "0": false, "no": false, "No": false, "off": false, "OFF": false, " true ": true,
	}
	for spelling, want := range accepted {
		t.Run("HEARTBEAT_ENABLED="+strings.TrimSpace(spelling), func(t *testing.T) {
			t.Setenv("HEARTBEAT_ENABLED", spelling)
			if want {
				// A complete heartbeat configuration so only the boolean is
				// under test.
				t.Setenv("HEARTBEAT_API_KEY", "k")
				t.Setenv("HEARTBEAT_APP", "a")
				t.Setenv("HEARTBEAT_URL", "https://hb.example.invalid/")
			}
			cfg, err := LoadFromEnv()
			if err != nil {
				t.Fatalf("%q must be accepted: %v", spelling, err)
			}
			if cfg.Heartbeat.Enabled != want {
				t.Fatalf("%q parsed as %v, want %v", spelling, cfg.Heartbeat.Enabled, want)
			}
		})
	}
	for _, spelling := range []string{"enabled", "y", "n", "2", "t", "f", "yes please", "  "} {
		t.Run("HEARTBEAT_ENABLED rejects "+strings.TrimSpace(spelling), func(t *testing.T) {
			t.Setenv("HEARTBEAT_ENABLED", spelling)
			_, err := LoadFromEnv()
			if err == nil || !strings.Contains(err.Error(), "HEARTBEAT_ENABLED") {
				t.Fatalf("%q must fail startup naming the variable: %v", spelling, err)
			}
		})
	}

	// Several malformed variables are reported together.
	t.Setenv("MAX_CONCURRENT", "lots")
	t.Setenv("RATE_LIMIT_BURST", "3.0")
	t.Setenv("HEARTBEAT_ENABLED", "maybe")
	_, err = LoadFromEnv()
	if err == nil {
		t.Fatal("malformed values must fail")
	}
	for _, v := range []string{"MAX_CONCURRENT", "RATE_LIMIT_BURST", "HEARTBEAT_ENABLED"} {
		if !strings.Contains(err.Error(), v) {
			t.Fatalf("every malformed variable is reported in one pass; missing %s in %v", v, err)
		}
	}
}
