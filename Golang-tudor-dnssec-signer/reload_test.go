package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/ptudor/dnssec-tudor/internal/config"
)

// R-006 / R-078: after a SIGHUP reload, the web UI and health endpoints must
// serve the *new* cfg/state, not the pointers captured when the servers were
// constructed. Before the fix the handler closures held the original cfg/state
// forever, so /api/status never showed newly added zones and /health went
// falsely 503 once the frozen zones' signatures aged past SignaturesExp.
//
// This test drives one server handler instance across a Reload and asserts it
// reflects post-reload state. It fails against the pre-fix code (frozen state).
func TestDaemonReload_HandlersReflectNewState(t *testing.T) {
	// Writable dirs so the only health signal under test is the zone's
	// signature expiry, not a directory-writability failure.
	dataDir := t.TempDir()
	outDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "keys"), 0700); err != nil {
		t.Fatal(err)
	}

	newCfg := func() *config.Config {
		return &config.Config{
			OutputDir:    outDir,
			DataDir:      dataDir,
			PollInterval: config.Duration{Duration: 5 * time.Minute},
			Web:          config.WebConfig{Enabled: true, Listen: "127.0.0.1:0"},
			Health:       config.HealthConfig{Listen: "127.0.0.1:0", ShutdownTimeout: config.Duration{Duration: 5 * time.Second}},
			Zones:        make(map[string]config.ZoneConfig),
		}
	}

	// Initial state: one zone whose signatures already expired -> /health 503.
	cfg1 := newCfg()
	cfg1.Zones["old.example."] = config.ZoneConfig{Path: "/zones/old.db"}
	state1 := statepkg.NewState(cfg1.StatePath())
	state1.SetZone("old.example.", &statepkg.ZoneState{Serial: 1, SignaturesExp: time.Now().Add(-24 * time.Hour)})

	// Post-reload state: a different zone with fresh (future) signatures.
	cfg2 := newCfg()
	cfg2.Zones["new.example."] = config.ZoneConfig{Path: "/zones/new.db"}
	state2 := statepkg.NewState(cfg2.StatePath())
	// A zone that is ready: keys initialized, signed and confirmed served
	// (RA6X-033 makes readiness fail for anything less).
	state2.SetZone("new.example.", &statepkg.ZoneState{
		Serial: 2, SignaturesExp: time.Now().Add(14 * 24 * time.Hour),
		KSK: &statepkg.KeyState{ID: 1, Algorithm: "ED25519"}, ZSK: &statepkg.KeyState{ID: 2, Algorithm: "ED25519"},
		LastSigned: time.Now(), PublishedAt: time.Now(), PublishedGenerationSignedAt: time.Now(),
	})

	d := NewDaemon(cfg1, state1)
	// One server handler instance, constructed once — exactly the startup wiring.
	handler := NewWebServer(d).Handler

	get := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		return rr
	}

	// --- Before reload: old state is served. ---
	if body := get("/api/status").Body.String(); !strings.Contains(body, "old.example.") {
		t.Fatalf("pre-reload /api/status should list old.example.: %s", body)
	}
	if rr := get("/health"); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("pre-reload /health should be 503 (old zone expired), got %d", rr.Code)
	}

	// --- Reload with new cfg/state. ---
	d.Reload(cfg2, state2)

	// --- After reload: the SAME handler now serves the new state. ---
	statusBody := get("/api/status").Body.String()
	if !strings.Contains(statusBody, "new.example.") {
		t.Errorf("post-reload /api/status must list new.example.: %s", statusBody)
	}
	if strings.Contains(statusBody, "old.example.") {
		t.Errorf("post-reload /api/status must not still list old.example.: %s", statusBody)
	}

	// The core R-006 regression: /health must reflect the new zone (not expired)
	// and return healthy instead of the frozen old zone's false 503.
	if rr := get("/health"); rr.Code != http.StatusOK {
		t.Errorf("post-reload /health must be 200 (new zone not expired), got %d: %s", rr.Code, rr.Body.String())
	}
	if rr := get("/healthz"); rr.Code != http.StatusOK {
		t.Errorf("post-reload /healthz must be 200, got %d", rr.Code)
	}
}
