package main

import (
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// RDAYBLUEX-023 subprocess regression: a huge positive cleanup interval makes
// the real binary exit with a configuration error at startup instead of
// panicking in the rate limiter's ticker goroutine. The binary is built once
// into a scratch directory and run with `-check` (which loads and validates
// the configuration exactly as a start would, without listening).
func TestRDAYBLUEX023_HugeCleanupIntervalExitsWithConfigError(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "sigillum-validator-test")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("building the binary: %v", err)
	}
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[rate_limit]\ncleanup_seconds = "+strings.TrimSpace(strings.Repeat("9", 18))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := exec.Command(bin, "-check", "-config", cfgPath)
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("the process must exit non-zero on an overflowing cleanup interval, output: %s", out)
	}
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() == 2 && strings.Contains(string(out), "panic") {
		t.Fatalf("expected a configuration error exit, got %v: %s", err, out)
	}
	if strings.Contains(string(out), "panic") {
		t.Fatalf("the process must not panic: %s", out)
	}
	if !strings.Contains(string(out), "cleanup_seconds") {
		t.Fatalf("the error must name the field: %s", out)
	}
	// And through the environment fallback, with no config file at all.
	run = exec.Command(bin, "-check")
	run.Dir = t.TempDir()
	run.Env = append(os.Environ(), "RATE_LIMIT_CLEANUP_SECONDS="+strings.TrimSpace(strings.Repeat("9", 18)))
	out, err = run.CombinedOutput()
	if err == nil || strings.Contains(string(out), "panic") || !strings.Contains(string(out), "cleanup_seconds") {
		t.Fatalf("the environment path must fail the same way, err=%v: %s", err, out)
	}
	_ = math.MaxInt64
}
