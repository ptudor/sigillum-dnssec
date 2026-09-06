package main

import (
	"os"
	"path/filepath"
	"testing"
)

// R-041: the daemon writability probe must never open/truncate/remove a
// pre-existing fixed-name ".startup_check" file — a unique temp is used instead.
func TestR041_StartupProbePreservesExistingFile(t *testing.T) {
	dir := t.TempDir()

	// An operator/tooling file that happens to be named ".startup_check".
	victim := filepath.Join(dir, ".startup_check")
	const content = "operator-owned data that must survive"
	if err := os.WriteFile(victim, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{}
	if err := d.checkDirWritable(dir, "data"); err != nil {
		t.Fatalf("checkDirWritable on a writable dir should succeed: %v", err)
	}

	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatalf("pre-existing .startup_check was destroyed by the probe: %v", err)
	}
	if string(got) != content {
		t.Fatalf(".startup_check content changed: got %q, want %q", got, content)
	}

	// No leftover temp probe files remain.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != ".startup_check" {
			t.Errorf("probe left a leftover file: %s", e.Name())
		}
	}
}
