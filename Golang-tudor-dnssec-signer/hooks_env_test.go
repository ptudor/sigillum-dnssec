package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ptudor/dnssec-tudor/internal/config"
)

// TestExecuteHookSync_Env verifies the CLI hook path exports the same
// DNSSEC_* environment the daemon's async hook provides.
func TestExecuteHookSync_Env(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "hook.out")
	hooks := &config.HooksConfig{
		PostSignCmd: []string{"/bin/sh", "-c", "echo \"$DNSSEC_DOMAIN $DNSSEC_SIGNED_PATH\" > " + outFile},
	}
	env := &HookEnv{
		Domain:     "example.com",
		ZonePath:   "/tmp/zone",
		SignedPath: "/tmp/signed",
		OutputDir:  "/tmp",
	}
	if err := executeHookSync(hooks, env); err != nil {
		t.Fatalf("executeHookSync: %v", err)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("hook output not written: %v", err)
	}
	got := strings.TrimSpace(string(data))
	if got != "example.com /tmp/signed" {
		t.Errorf("hook env = %q, want %q", got, "example.com /tmp/signed")
	}
}
