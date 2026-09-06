//go:build !windows

package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RA6X-006: daemon startup must not write state outside the lock protocol, and
// a duplicate instance is refused before any shared-state mutation.

func TestRA6X006_StartupValidationDoesNotWriteState(t *testing.T) {
	d, cfg, _, _ := signableZoneDaemon(t)
	// A newer state committed by "someone else" (a CLI) before startup validates.
	other := statepkg.NewState(cfg.StatePath())
	other.SetZone("cli-added.example.", &statepkg.ZoneState{Path: "/z/cli.zone"})
	if err := other.Save(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ensureDirectories(cfg); err != nil {
		t.Fatal(err)
	}
	if err := d.validateStartup(cfg); err != nil {
		t.Fatalf("validateStartup: %v", err)
	}
	after, err := os.ReadFile(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("startup validation must not rewrite state.json with the daemon's stale snapshot")
	}
	// The first cycle adopts the CLI's zone under the lock instead of clobbering it.
	d.signAllZones()
	reloaded, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.GetZone("cli-added.example.") == nil {
		t.Fatal("a zone committed by a CLI before the first cycle must survive the daemon's save")
	}
}

func TestRA6X006_DuplicateInstanceRefusedAndStateUntouched(t *testing.T) {
	d, cfg, _, _ := signableZoneDaemon(t)
	if err := d.state.Save(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfg.StatePath())

	// Instance lock: a second acquisition fails immediately.
	first, err := acquireInstanceLock(cfg.DataDir)
	if err != nil {
		t.Fatalf("first instance lock: %v", err)
	}
	defer first.release()
	if _, err := acquireInstanceLock(cfg.DataDir); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Fatalf("a second instance must be refused, got %v", err)
	}

	// Startup that fails at port binding must leave state and keys byte-for-byte unchanged.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg.Health.Listen = ln.Addr().String()
	keyFiles, _ := filepath.Glob(filepath.Join(cfg.KeysDir(), "*"))
	keyBytes := map[string][]byte{}
	for _, f := range keyFiles {
		b, _ := os.ReadFile(f)
		keyBytes[f] = b
	}
	if err := d.Run(); err == nil {
		t.Fatal("Run must fail when the health port is already bound")
	}
	after, _ := os.ReadFile(cfg.StatePath())
	if string(before) != string(after) {
		t.Fatal("a failed startup must not modify state.json")
	}
	for f, b := range keyBytes {
		got, _ := os.ReadFile(f)
		if string(got) != string(b) {
			t.Fatalf("a failed startup must not modify key file %s", f)
		}
	}
}

func TestRA6X006_LoadStateLockedWaitsForCLICommit(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	// A CLI holds the state lock while it commits a rollover record.
	lock, err := acquireStateLock(cfg.DataDir, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *statepkg.State, 1)
	go func() {
		st, err := loadStateLocked(cfg)
		if err != nil {
			t.Error(err)
		}
		done <- st
	}()
	time.Sleep(150 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("startup load must wait for the state lock")
	default:
	}
	state.UpdateZone(domain, func(zs *statepkg.ZoneState) { zs.AddWarning("URGENT: committed by cli") })
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	lock.release()
	select {
	case st := <-done:
		if st == nil || len(st.GetZone(domain).Warnings) != 1 {
			t.Fatal("startup load must observe the CLI's commit")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup load did not complete after the lock was released")
	}
}

// RA6X-026: a cycle whose authoritative state cannot be loaded fails closed.
func TestRA6X026_UnreadableStateFailsCycleClosed(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	signed := filepath.Join(cfg.OutputDir, domain+".zone.signed")

	// Replace state.json with malformed JSON.
	if err := os.WriteFile(cfg.StatePath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	d.signAllZones()
	if _, err := os.Stat(signed); err == nil {
		t.Fatal("no zone may be signed while the state is unreadable")
	}
	if got, _ := os.ReadFile(cfg.StatePath()); string(got) != "{not json" {
		t.Fatal("the unreadable state file must be preserved as evidence, not overwritten")
	}
	if d.StateFault() == "" {
		t.Fatal("the cycle failure must be exposed as a persistent state fault")
	}
	// Readiness reports the blocked cycle.
	rec := httptest.NewRecorder()
	healthzHandler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil), state, cfg, d)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("/healthz = %d, want 503 while the state is unloadable", rec.Code)
	}
	rec = httptest.NewRecorder()
	healthHandler(rec, httptest.NewRequest(http.MethodGet, "/health", nil), state, cfg, d)
	if !strings.Contains(rec.Body.String(), "state:") {
		t.Fatalf("/health must name the state fault: %s", rec.Body.String())
	}

	// Repair the file: the next cycle proceeds and the fault clears.
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	d.signAllZones()
	if _, err := os.Stat(signed); err != nil {
		t.Fatalf("zone must be signed once the state is readable again: %v", err)
	}
	if d.StateFault() != "" {
		t.Fatalf("state fault must clear after a successful load, got %q", d.StateFault())
	}

	// A vanished file is likewise fail-closed with the explicit recovery hint.
	if err := os.Remove(cfg.StatePath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(signed); err != nil {
		t.Fatal(err)
	}
	state.UpdateZone(domain, func(zs *statepkg.ZoneState) { zs.ForceResign = true })
	d.signAllZones()
	if _, err := os.Stat(signed); err == nil {
		t.Fatal("no signing while the state file is missing")
	}
	if _, err := os.Stat(cfg.StatePath()); err == nil {
		t.Fatal("a missing state file must not be silently recreated from memory")
	}
	if !strings.Contains(d.StateFault(), "restart the daemon") {
		t.Fatalf("the fault must carry the explicit recovery instruction, got %q", d.StateFault())
	}
}

// RA6X-026: an interrupted CLI key transition (state file invalid mid-way) must
// not be signed through with stale in-memory keys.
func TestRA6X026_InvalidStateIsNotSignedThrough(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	// A rollover record with an impossible phase lands on disk.
	doc := `{"zones": {"` + domain + `": {"path": "` + cfg.Zones[domain].Path + `", "ksk": {"id": 1, "algorithm": "ED25519"}, "zsk": {"id": 2, "algorithm": "ED25519"}, "rollover": {"type": "ksk", "state": "half_done", "old_key_id": 1, "new_key_id": 3}}}}`
	if err := os.WriteFile(cfg.StatePath(), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	d.signAllZones()
	if _, err := os.Stat(filepath.Join(cfg.OutputDir, domain+".zone.signed")); err == nil {
		t.Fatal("an invalid rollover record on disk must block signing, not be interpreted as ordinary operation")
	}
	if got, _ := os.ReadFile(cfg.StatePath()); string(got) != doc {
		t.Fatal("the invalid state must be left for the operator")
	}
}
