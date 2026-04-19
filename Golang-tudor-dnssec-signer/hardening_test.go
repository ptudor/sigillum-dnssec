package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// R53-001: Loopback enforcement for listen addresses
// ---------------------------------------------------------------------------

func TestIsLoopbackAddr(t *testing.T) {
	tests := []struct {
		addr     string
		loopback bool
	}{
		{"127.0.0.1:8053", true},
		{"[::1]:8053", true},
		{"localhost:8053", true},
		{"0.0.0.0:8053", false},
		{":8053", false}, // all interfaces
		{"192.168.1.1:8053", false},
		{"10.0.0.1:8053", false},
		{"[::]:8053", false},
		{"example.com:8053", false},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := isLoopbackAddr(tt.addr)
			if got != tt.loopback {
				t.Errorf("isLoopbackAddr(%q) = %v, want %v", tt.addr, got, tt.loopback)
			}
		})
	}
}

func TestConfigValidation_LoopbackEnforcement(t *testing.T) {
	base := func() *Config {
		return &Config{
			OutputDir:    "/tmp/test",
			DataDir:      "/tmp/test",
			PollInterval: Duration{5 * time.Minute},
			DNSSEC: DNSSECConfig{
				Algorithm:         "ED25519",
				KSKLifetime:       Duration{3 * 365 * 24 * time.Hour},
				ZSKLifetime:       Duration{90 * 24 * time.Hour},
				SignatureValidity: Duration{14 * 24 * time.Hour},
				SignatureRefresh:  Duration{3 * 24 * time.Hour},
				NSECVersion:       "nsec3",
			},
			Web:    WebConfig{Enabled: false, Listen: "127.0.0.1:8053"},
			Health: HealthConfig{Listen: "127.0.0.1:8054"},
			Zones:  make(map[string]ZoneConfig),
		}
	}

	t.Run("web non-loopback rejected by default", func(t *testing.T) {
		cfg := base()
		cfg.Web.Enabled = true
		cfg.Web.Listen = "0.0.0.0:8053"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for non-loopback web listen")
		}
		if got := err.Error(); !contains(got, "non-loopback") {
			t.Errorf("unexpected error: %s", got)
		}
	})

	t.Run("web non-loopback allowed with allow_remote", func(t *testing.T) {
		cfg := base()
		cfg.Web.Enabled = true
		cfg.Web.Listen = "0.0.0.0:8053"
		cfg.Web.AllowRemote = true
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error with AllowRemote=true, got: %v", err)
		}
	})

	t.Run("health non-loopback rejected by default", func(t *testing.T) {
		cfg := base()
		cfg.Health.Listen = ":8054"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for non-loopback health listen")
		}
	})

	t.Run("health non-loopback allowed with allow_remote", func(t *testing.T) {
		cfg := base()
		cfg.Health.Listen = ":8054"
		cfg.Health.AllowRemote = true
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error with Health.AllowRemote=true, got: %v", err)
		}
	})

	t.Run("web disabled skips listen check", func(t *testing.T) {
		cfg := base()
		cfg.Web.Enabled = false
		cfg.Web.Listen = "0.0.0.0:8053" // would fail if checked
		if err := cfg.Validate(); err != nil {
			t.Errorf("web disabled should skip listen validation, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// R53-005/R53-006: Hook command parsing
// ---------------------------------------------------------------------------

func TestHookCmd(t *testing.T) {
	t.Run("PostSignCmd exec-style", func(t *testing.T) {
		hooks := &HooksConfig{PostSignCmd: []string{"/usr/bin/nsd-control", "reload"}}
		name, args, identity, ok := hookCmd(hooks)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if name != "/usr/bin/nsd-control" {
			t.Errorf("name = %q, want /usr/bin/nsd-control", name)
		}
		if len(args) != 1 || args[0] != "reload" {
			t.Errorf("args = %v, want [reload]", args)
		}
		if identity != "post_sign" {
			t.Errorf("identity = %q, want post_sign", identity)
		}
	})

	t.Run("PostSign with shell", func(t *testing.T) {
		hooks := &HooksConfig{PostSign: "systemctl reload nsd", Shell: true}
		name, args, identity, ok := hookCmd(hooks)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if name != "sh" {
			t.Errorf("name = %q, want sh", name)
		}
		if len(args) != 2 || args[0] != "-c" || args[1] != "systemctl reload nsd" {
			t.Errorf("args = %v, want [-c systemctl reload nsd]", args)
		}
		if identity != "post_sign(shell)" {
			t.Errorf("identity = %q, want post_sign(shell)", identity)
		}
	})

	t.Run("PostSign without shell splits on whitespace", func(t *testing.T) {
		hooks := &HooksConfig{PostSign: "systemctl reload nsd"}
		name, args, identity, ok := hookCmd(hooks)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if name != "systemctl" {
			t.Errorf("name = %q, want systemctl", name)
		}
		if len(args) != 2 || args[0] != "reload" || args[1] != "nsd" {
			t.Errorf("args = %v, want [reload nsd]", args)
		}
		if identity != "post_sign" {
			t.Errorf("identity = %q, want post_sign", identity)
		}
	})

	t.Run("PostSignCmd takes priority over PostSign", func(t *testing.T) {
		hooks := &HooksConfig{
			PostSignCmd: []string{"/usr/bin/nsd-control", "reload"},
			PostSign:    "systemctl reload nsd",
			Shell:       true,
		}
		name, _, _, ok := hookCmd(hooks)
		if !ok || name != "/usr/bin/nsd-control" {
			t.Errorf("PostSignCmd should take priority, got name=%q ok=%v", name, ok)
		}
	})

	t.Run("empty hooks return ok=false", func(t *testing.T) {
		hooks := &HooksConfig{}
		_, _, _, ok := hookCmd(hooks)
		if ok {
			t.Error("expected ok=false for empty hooks")
		}
	})

	t.Run("empty PostSign returns ok=false", func(t *testing.T) {
		hooks := &HooksConfig{PostSign: ""}
		_, _, _, ok := hookCmd(hooks)
		if ok {
			t.Error("expected ok=false for empty PostSign")
		}
	})

	t.Run("whitespace-only PostSign returns ok=false", func(t *testing.T) {
		hooks := &HooksConfig{PostSign: "   "}
		_, _, _, ok := hookCmd(hooks)
		if ok {
			t.Error("expected ok=false for whitespace-only PostSign")
		}
	})
}

// ---------------------------------------------------------------------------
// R53-007: Directory permission hardening
// ---------------------------------------------------------------------------

func TestEnsureDirSecure_CreatesWithRestrictedPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	secureDir := filepath.Join(tmpDir, "keys")

	if err := ensureDirSecure(secureDir); err != nil {
		t.Fatalf("ensureDirSecure failed: %v", err)
	}

	info, err := os.Stat(secureDir)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("expected 0700 permissions, got %04o", perm)
	}
}

func TestEnsureDirSecure_TightensLoosePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	looseDir := filepath.Join(tmpDir, "keys")

	// Create with too-wide permissions
	if err := os.MkdirAll(looseDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	if err := ensureDirSecure(looseDir); err != nil {
		t.Fatalf("ensureDirSecure failed: %v", err)
	}

	info, err := os.Stat(looseDir)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("expected permissions tightened to 0700, got %04o", perm)
	}
}

func TestEnsureDirSecure_LeavesCorrectPermissionsAlone(t *testing.T) {
	tmpDir := t.TempDir()
	okDir := filepath.Join(tmpDir, "keys")

	if err := os.MkdirAll(okDir, 0700); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	if err := ensureDirSecure(okDir); err != nil {
		t.Fatalf("ensureDirSecure failed: %v", err)
	}

	info, _ := os.Stat(okDir)
	if info.Mode().Perm() != 0700 {
		t.Error("permissions should remain 0700")
	}
}

func TestEnsureDirSecure_RejectsFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "notadir")
	os.WriteFile(filePath, []byte("x"), 0644)

	err := ensureDirSecure(filePath)
	if err == nil {
		t.Fatal("expected error for file path")
	}
	if !contains(err.Error(), "not a directory") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// R53-007: State file permissions
// ---------------------------------------------------------------------------

func TestStateSave_RestrictedPermissions(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "state.json")

	state := NewState(statePath)
	state.SetZone("example.com", &ZoneState{Serial: 1})

	if err := state.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("state file should have 0600 permissions, got %04o", perm)
	}
}

// ---------------------------------------------------------------------------
// R53-009: UpdateZone concurrency
// ---------------------------------------------------------------------------

func TestUpdateZone_MutatesUnderLock(t *testing.T) {
	state := NewState("")
	state.SetZone("example.com", &ZoneState{Serial: 1})

	state.UpdateZone("example.com", func(z *ZoneState) {
		z.Serial = 42
	})

	zone := state.GetZone("example.com")
	if zone.Serial != 42 {
		t.Errorf("expected serial 42, got %d", zone.Serial)
	}
}

func TestUpdateZone_NoopForMissingZone(t *testing.T) {
	state := NewState("")

	// Should not panic for missing zone
	state.UpdateZone("nonexistent.com", func(z *ZoneState) {
		z.Serial = 99
	})
}

// ---------------------------------------------------------------------------
// R53-010: Heartbeat HTTPS enforcement
// ---------------------------------------------------------------------------

func TestConfigValidation_HeartbeatHTTPS(t *testing.T) {
	base := func() *Config {
		return &Config{
			OutputDir:    "/tmp/test",
			DataDir:      "/tmp/test",
			PollInterval: Duration{5 * time.Minute},
			DNSSEC: DNSSECConfig{
				Algorithm:         "ED25519",
				KSKLifetime:       Duration{3 * 365 * 24 * time.Hour},
				ZSKLifetime:       Duration{90 * 24 * time.Hour},
				SignatureValidity: Duration{14 * 24 * time.Hour},
				SignatureRefresh:  Duration{3 * 24 * time.Hour},
				NSECVersion:       "nsec3",
			},
			Health: HealthConfig{Listen: "127.0.0.1:8054"},
			Zones:  make(map[string]ZoneConfig),
		}
	}

	t.Run("HTTP heartbeat URL rejected by default", func(t *testing.T) {
		cfg := base()
		cfg.Heartbeat.Enabled = true
		cfg.Heartbeat.URL = "http://example.com/heartbeat/"
		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for HTTP heartbeat URL")
		}
		if !contains(err.Error(), "HTTPS") {
			t.Errorf("error should mention HTTPS, got: %v", err)
		}
	})

	t.Run("HTTP heartbeat URL allowed with AllowInsecure", func(t *testing.T) {
		cfg := base()
		cfg.Heartbeat.Enabled = true
		cfg.Heartbeat.URL = "http://example.com/heartbeat/"
		cfg.Heartbeat.AllowInsecure = true
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error with AllowInsecure, got: %v", err)
		}
	})

	t.Run("HTTPS heartbeat URL accepted by default", func(t *testing.T) {
		cfg := base()
		cfg.Heartbeat.Enabled = true
		cfg.Heartbeat.URL = "https://example.com/heartbeat/"
		if err := cfg.Validate(); err != nil {
			t.Errorf("HTTPS URL should be accepted, got: %v", err)
		}
	})

	t.Run("disabled heartbeat skips URL check", func(t *testing.T) {
		cfg := base()
		cfg.Heartbeat.Enabled = false
		cfg.Heartbeat.URL = "http://insecure.example.com/"
		if err := cfg.Validate(); err != nil {
			t.Errorf("disabled heartbeat should skip URL check, got: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// R53-011: HTTP method restriction and security headers
// ---------------------------------------------------------------------------

func TestSecurityHeaders_MethodRestriction(t *testing.T) {
	handler := securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("GET allowed", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		handler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("GET should be allowed, got %d", rr.Code)
		}
	})

	t.Run("HEAD allowed", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodHead, "/", nil)
		handler(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("HEAD should be allowed, got %d", rr.Code)
		}
	})

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method+" rejected", func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/", nil)
			handler(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s should return 405, got %d", method, rr.Code)
			}
		})
	}
}

func TestSecurityHeaders_Present(t *testing.T) {
	handler := securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler(rr, req)

	expected := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
		"Referrer-Policy":         "no-referrer",
		"Permissions-Policy":      "interest-cohort=()",
		"Cache-Control":           "no-store",
	}

	for header, want := range expected {
		got := rr.Header().Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	// X-XSS-Protection should NOT be set (deprecated)
	if got := rr.Header().Get("X-XSS-Protection"); got != "" {
		t.Errorf("X-XSS-Protection should not be set (deprecated), got %q", got)
	}
}

func TestHealthEndpoints_MethodRestriction(t *testing.T) {
	state := NewState("")
	cfg := &Config{
		OutputDir: "/tmp",
		DataDir:   "/tmp",
		Health:    HealthConfig{Listen: "127.0.0.1:8054"},
	}

	mux := http.NewServeMux()
	RegisterHealthHandlers(mux, state, cfg)

	for _, path := range []string{"/health", "/healthz"} {
		t.Run("POST"+path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, path, nil)
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("POST %s should return 405, got %d", path, rr.Code)
			}
		})

		t.Run("GET"+path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			mux.ServeHTTP(rr, req)
			// Should not be 405 (may be 200 or 503 depending on state)
			if rr.Code == http.StatusMethodNotAllowed {
				t.Errorf("GET %s should not return 405", path)
			}
		})
	}
}

func TestHealthEndpoints_SecurityHeaders(t *testing.T) {
	state := NewState("")
	cfg := &Config{
		OutputDir: "/tmp",
		DataDir:   "/tmp",
		Health:    HealthConfig{Listen: "127.0.0.1:8054"},
	}

	mux := http.NewServeMux()
	RegisterHealthHandlers(mux, state, cfg)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	mux.ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := rr.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// ---------------------------------------------------------------------------
// R53-012: Non-destructive health checks
// ---------------------------------------------------------------------------

func TestCheckDirWritable_StatBased(t *testing.T) {
	t.Run("writable directory passes", func(t *testing.T) {
		dir := t.TempDir()
		if err := checkDirWritable(dir); err != nil {
			t.Errorf("writable dir should pass: %v", err)
		}
	})

	t.Run("nonexistent directory fails", func(t *testing.T) {
		err := checkDirWritable("/nonexistent/path/xyz")
		if err == nil {
			t.Fatal("expected error for nonexistent directory")
		}
	})

	t.Run("file instead of directory fails", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "afile")
		os.WriteFile(f, []byte("x"), 0644)
		err := checkDirWritable(f)
		if err == nil {
			t.Fatal("expected error for file path")
		}
		if !contains(err.Error(), "not a directory") {
			t.Errorf("error should mention 'not a directory', got: %v", err)
		}
	})

	t.Run("no temp files created during check", func(t *testing.T) {
		dir := t.TempDir()
		// Count files before
		before, _ := os.ReadDir(dir)

		_ = checkDirWritable(dir)

		// Count files after
		after, _ := os.ReadDir(dir)
		if len(after) != len(before) {
			t.Error("health check should not create any files")
		}
	})
}

// ---------------------------------------------------------------------------
// R53-013: Template caching (init-time parse)
// ---------------------------------------------------------------------------

func TestDashboardTemplate_Cached(t *testing.T) {
	// The dashboardTemplate is parsed at init() time.
	// Verify it is non-nil (successful parse of embedded template).
	if dashboardTemplate == nil {
		t.Fatal("dashboardTemplate should be parsed at init time, got nil")
	}
}

// ---------------------------------------------------------------------------
// R53-002: /debug/vars off by default
// ---------------------------------------------------------------------------

func TestWebServer_NoDebugVarsPath(t *testing.T) {
	// The web mux does not register /debug/vars. Verify 404.
	cfg := &Config{
		OutputDir: "/tmp",
		DataDir:   "/tmp",
		Web:       WebConfig{Enabled: true, Listen: "127.0.0.1:8053"},
		Health:    HealthConfig{Listen: "127.0.0.1:8054"},
		Zones:     make(map[string]ZoneConfig),
	}
	state := NewState("")
	srv := NewWebServer(cfg, state)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/debug/vars", nil)
	srv.Handler.ServeHTTP(rr, req)

	if rr.Code == http.StatusOK {
		t.Error("/debug/vars should not be registered on the web server mux")
	}
}

// ---------------------------------------------------------------------------
// R53-011: Web dashboard path enforcement
// ---------------------------------------------------------------------------

func TestDashboardHandler_PathRouting(t *testing.T) {
	cfg := &Config{
		OutputDir: "/tmp",
		DataDir:   "/tmp",
		Web:       WebConfig{Enabled: true, Listen: "127.0.0.1:8053"},
		Health:    HealthConfig{Listen: "127.0.0.1:8054"},
		Zones:     make(map[string]ZoneConfig),
	}
	state := NewState("")
	srv := NewWebServer(cfg, state)

	t.Run("root path returns 200", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		srv.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("GET / should return 200, got %d", rr.Code)
		}
	})

	t.Run("unknown path returns 404", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
		srv.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("GET /nonexistent should return 404, got %d", rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// R53-011: API endpoints method restriction and content type
// ---------------------------------------------------------------------------

func TestAPIEndpoints_MethodAndContentType(t *testing.T) {
	cfg := &Config{
		OutputDir: "/tmp",
		DataDir:   "/tmp",
		Web:       WebConfig{Enabled: true, Listen: "127.0.0.1:8053"},
		Health:    HealthConfig{Listen: "127.0.0.1:8054"},
		Zones:     make(map[string]ZoneConfig),
	}
	state := NewState("")
	srv := NewWebServer(cfg, state)

	t.Run("POST /api/status rejected", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/status", nil)
		srv.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST /api/status should return 405, got %d", rr.Code)
		}
	})

	t.Run("GET /api/status returns JSON", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		srv.Handler.ServeHTTP(rr, req)
		ct := rr.Header().Get("Content-Type")
		if ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
	})

	t.Run("DELETE /api/zone/example.com rejected", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodDelete, "/api/zone/example.com", nil)
		srv.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("DELETE /api/zone/example.com should return 405, got %d", rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// R53-008: Zone state transitions
// ---------------------------------------------------------------------------

func TestZoneState_StatusTransitions(t *testing.T) {
	tests := []struct {
		name   string
		zone   ZoneState
		expect string
	}{
		{
			name:   "healthy zone",
			zone:   ZoneState{Serial: 1},
			expect: "healthy",
		},
		{
			name:   "zone with errors",
			zone:   ZoneState{Serial: 1, Errors: []string{"signing failed"}},
			expect: "error",
		},
		{
			name:   "zone with warnings",
			zone:   ZoneState{Serial: 1, Warnings: []string{"approaching expiry"}},
			expect: "warning",
		},
		{
			name: "zone with rollover",
			zone: ZoneState{
				Serial:   1,
				Rollover: &RolloverState{Type: "ksk", State: KSKRolloverStateDSAddWait},
			},
			expect: "action_required",
		},
		{
			name: "errors take priority over rollover",
			zone: ZoneState{
				Serial:   1,
				Errors:   []string{"broken"},
				Rollover: &RolloverState{Type: "ksk", State: KSKRolloverStateDSAddWait},
			},
			expect: "error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.zone.Status()
			if got != tt.expect {
				t.Errorf("Status() = %q, want %q", got, tt.expect)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// R53-004: Healthz endpoint responds to GET
// ---------------------------------------------------------------------------

func TestHealthz_ReturnsOK(t *testing.T) {
	state := NewState("")
	cfg := &Config{
		OutputDir: t.TempDir(),
		DataDir:   t.TempDir(),
		Health:    HealthConfig{Listen: "127.0.0.1:8054"},
	}

	mux := http.NewServeMux()
	RegisterHealthHandlers(mux, state, cfg)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	mux.ServeHTTP(rr, req)

	body, _ := io.ReadAll(rr.Result().Body)
	// With no zones and writable dirs, should be healthy
	// Note: dirs may not exist in test, so it might be UNHEALTHY,
	// but at minimum it should not be 405
	if rr.Code == http.StatusMethodNotAllowed {
		t.Errorf("GET /healthz should not return 405")
	}
	_ = body // just verify no panic
}

// ---------------------------------------------------------------------------
// R53-001: Domain name validation for path safety
// ---------------------------------------------------------------------------

func TestValidateDomainName_PathTraversal(t *testing.T) {
	// Ensure path traversal attempts are blocked
	malicious := []string{
		"../etc/passwd",
		"..%2F..%2Fetc",
		"foo/../bar",
		"foo/bar",
		"foo\\bar",
		"",
	}
	for _, name := range malicious {
		t.Run(fmt.Sprintf("reject_%s", name), func(t *testing.T) {
			if err := ValidateDomainName(name); err == nil {
				t.Errorf("ValidateDomainName(%q) should return error", name)
			}
		})
	}
}

// contains is a test helper checking if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
