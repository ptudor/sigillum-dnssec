package config

import (
	"strings"
	"testing"
	"time"
)

// RDAYBLUEX-014: the registrar base_url override must be HTTPS, or http
// only for a loopback host behind allow_insecure_base_url.
func TestRDAYBLUEX014_ValidateRegistrarBaseURL(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		allow  bool
		wantOK bool
		want   string
	}{
		{"empty", "", false, true, ""},
		{"https", "https://proxy.example.invalid", false, true, ""},
		{"https with path", "https://proxy.example.invalid/api/", false, true, ""},
		{"cleartext public", "http://proxy.example.invalid", false, false, "https"},
		{"cleartext public with override", "http://proxy.example.invalid", true, false, "loopback"},
		{"cleartext loopback without override", "http://127.0.0.1:8088", false, false, "https"},
		{"cleartext loopback with override", "http://127.0.0.1:8088", true, true, ""},
		{"cleartext localhost with override", "http://localhost:8088", true, true, ""},
		{"cleartext v6 loopback with override", "http://[::1]:8088", true, true, ""},
		{"relative", "/api", false, false, "absolute"},
		{"userinfo", "https://k:s@proxy.example.invalid", false, false, "userinfo"},
		{"query", "https://proxy.example.invalid/?x", false, false, "query"},
		{"other scheme", "ftp://proxy.example.invalid", false, false, "scheme"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &RegistrarDynadotConfig{BaseURL: c.url, AllowInsecureBaseURL: c.allow}
			err := ValidateRegistrarBaseURL(cfg)
			if c.wantOK {
				if err != nil {
					t.Fatalf("%q must be accepted: %v", c.url, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%q must be rejected mentioning %q, got %v", c.url, c.want, err)
			}
		})
	}
}

// RDAYBLUEX-032: an enabled integration must be complete at load time, and
// errors name the field, never its value.
func TestRDAYBLUEX032_EnabledIntegrationsValidated(t *testing.T) {
	registrar := func(mutate func(*RegistrarDynadotConfig)) *Config {
		cfg := DefaultConfig()
		cfg.OutputDir, cfg.DataDir = "/tmp/out", "/tmp/data"
		cfg.Registrar.Dynadot = RegistrarDynadotConfig{Enabled: true, APIKey: "KEY-VALUE-SECRET", APISecret: "SECRET-VALUE", Timeout: Duration{30 * time.Second}}
		mutate(&cfg.Registrar.Dynadot)
		return cfg
	}
	heartbeat := func(mutate func(*HeartbeatConfig)) *Config {
		cfg := DefaultConfig()
		cfg.OutputDir, cfg.DataDir = "/tmp/out", "/tmp/data"
		cfg.Heartbeat = HeartbeatConfig{Enabled: true, URL: "https://status.example.invalid/hb", APIKey: "HB-KEY-VALUE", App: "signer", IntervalMinutes: 5}
		mutate(&cfg.Heartbeat)
		return cfg
	}
	cases := []struct {
		name string
		cfg  *Config
		want string // "" = valid
	}{
		{"registrar complete", registrar(func(*RegistrarDynadotConfig) {}), ""},
		{"registrar disabled and empty", registrar(func(r *RegistrarDynadotConfig) { r.Enabled = false; r.APIKey = ""; r.APISecret = "" }), ""},
		{"registrar missing key", registrar(func(r *RegistrarDynadotConfig) { r.APIKey = "" }), "api_key"},
		{"registrar whitespace key", registrar(func(r *RegistrarDynadotConfig) { r.APIKey = "  \n" }), "api_key"},
		{"registrar missing secret", registrar(func(r *RegistrarDynadotConfig) { r.APISecret = "" }), "api_secret"},
		{"registrar cleartext base_url", registrar(func(r *RegistrarDynadotConfig) { r.BaseURL = "http://proxy.example.invalid" }), "base_url"},
		{"heartbeat complete", heartbeat(func(*HeartbeatConfig) {}), ""},
		{"heartbeat disabled and empty", heartbeat(func(h *HeartbeatConfig) {
			h.Enabled = false
			h.URL = ""
			h.APIKey = ""
			h.App = ""
			h.IntervalMinutes = 0
		}), ""},
		{"heartbeat missing url", heartbeat(func(h *HeartbeatConfig) { h.URL = "" }), "url"},
		{"heartbeat missing key", heartbeat(func(h *HeartbeatConfig) { h.APIKey = " " }), "api_key"},
		{"heartbeat missing app", heartbeat(func(h *HeartbeatConfig) { h.App = "" }), "app"},
		{"heartbeat zero interval", heartbeat(func(h *HeartbeatConfig) { h.IntervalMinutes = 0 }), "interval_minutes"},
		{"heartbeat negative interval", heartbeat(func(h *HeartbeatConfig) { h.IntervalMinutes = -5 }), "interval_minutes"},
		{"heartbeat overflowed interval", heartbeat(func(h *HeartbeatConfig) { h.IntervalMinutes = 1 << 40 }), "interval_minutes"},
		{"heartbeat above a day", heartbeat(func(h *HeartbeatConfig) { h.IntervalMinutes = 24*60 + 1 }), "interval_minutes"},
		{"heartbeat one day", heartbeat(func(h *HeartbeatConfig) { h.IntervalMinutes = 24 * 60 }), ""},
		{"heartbeat cleartext url", heartbeat(func(h *HeartbeatConfig) { h.URL = "http://status.example.invalid/hb" }), "HTTPS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if c.want == "" {
				if err != nil {
					t.Fatalf("must validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("must fail mentioning %q, got %v", c.want, err)
			}
			for _, secret := range []string{"KEY-VALUE-SECRET", "SECRET-VALUE", "HB-KEY-VALUE"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("an error must never echo a secret value: %v", err)
				}
			}
		})
	}
}
