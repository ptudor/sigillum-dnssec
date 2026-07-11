package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Live-DNS validation of every zone is expensive (NS + DS/DNSKEY/SOA queries
// per zone, each with a multi-second timeout). Running it inline in the request
// on every `?validate=true` / `/api/validate` hit lets a client trigger repeated
// many-second, many-query runs and can blow past the 30s WriteTimeout. These
// bound it (R-043): results are cached for a short TTL, only one validation runs
// at a time (single-flight), and a request waits at most validationMaxWait for a
// fresh result before returning whatever is cached (possibly stale/nil) while
// the run finishes in the background.
const (
	validationCacheTTL = 30 * time.Second
	validationMaxWait  = 20 * time.Second // < the 30s WriteTimeout
)

type validationCache struct {
	mu       sync.Mutex
	result   *ValidateOutput
	computed time.Time
	inflight chan struct{} // non-nil while a computation runs; closed on completion
}

var dashboardValidationCache = &validationCache{}

// get returns a recent ValidateAll result. It serves a fresh cached result
// immediately, runs at most one computation at a time, and never blocks the
// caller longer than maxWait — on timeout it returns the last cached result
// (which may be nil on a cold start) while the in-flight computation continues.
func (c *validationCache) get(compute func() *ValidateOutput, ttl, maxWait time.Duration) *ValidateOutput {
	c.mu.Lock()
	if c.result != nil && time.Since(c.computed) < ttl {
		r := c.result
		c.mu.Unlock()
		return r
	}
	done := c.inflight
	if done == nil {
		done = make(chan struct{})
		c.inflight = done
		go func() {
			out := compute()
			c.mu.Lock()
			c.result = out
			c.computed = time.Now()
			c.inflight = nil
			c.mu.Unlock()
			close(done)
		}()
	}
	stale := c.result
	c.mu.Unlock()

	select {
	case <-done:
		c.mu.Lock()
		r := c.result
		c.mu.Unlock()
		return r
	case <-time.After(maxWait):
		return stale // may be nil; the background run will refresh the cache
	}
}

// cachedValidateAll is the bounded entry point the web handlers use instead of
// calling v.ValidateAll() directly.
func cachedValidateAll(v *Validator) *ValidateOutput {
	return dashboardValidationCache.get(v.ValidateAll, validationCacheTTL, validationMaxWait)
}

//go:embed templates/*.html
var templateFS embed.FS

// dashboardTemplate is parsed once at init and reused for every request.
var dashboardTemplate *template.Template

func init() {
	var err error
	dashboardTemplate, err = template.ParseFS(templateFS, "templates/index.html")
	if err != nil {
		// Template is embedded; a parse failure here is a build-time bug.
		panic("failed to parse embedded dashboard template: " + err.Error())
	}
}

// securityHeaders wraps a handler to add security headers and enforce GET-only.
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "interest-cohort=()")
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
	}
}

// NewWebServer creates a new HTTP server for the web UI. Handlers resolve the
// daemon's live cfg/state per request (d.current()) rather than closing over the
// pointers captured at startup, so the dashboard and health endpoints reflect a
// SIGHUP reload instead of serving frozen pre-reload state (R-006).
func NewWebServer(d *Daemon) *http.Server {
	mux := http.NewServeMux()

	// Register handlers with security headers
	mux.HandleFunc("/", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		cfg, state := d.current()
		dashboardHandler(w, r, cfg, state)
	}))
	mux.HandleFunc("/api/status", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		_, state := d.current()
		apiStatusHandler(w, r, state)
	}))
	mux.HandleFunc("/api/zone/", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		cfg, state := d.current()
		apiZoneHandler(w, r, cfg, state)
	}))
	mux.HandleFunc("/api/validate", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		cfg, state := d.current()
		apiValidateHandler(w, r, cfg, state)
	}))
	mux.HandleFunc("/api/validate/", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		cfg, state := d.current()
		apiValidateZoneHandler(w, r, cfg, state)
	}))

	// Health endpoints
	RegisterHealthHandlersWithDaemon(mux, d)

	// Addr is read once at construction — changing web.listen still requires a
	// restart (the listener is bound in Run before this server is created).
	cfg, _ := d.current()
	return &http.Server{
		Addr:              cfg.Web.Listen,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request, cfg *Config, state *State) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	status := state.ToStatusOutput()

	// Compute DS records for each zone to display inline. Only the public
	// key halves are read — the dashboard must never touch .private files.
	dsRecords := make(map[string]string)
	keyGen := NewKeyGenerator(cfg)
	for domain, zone := range status.Zones {
		if zone.KSK != nil {
			ksk, err := keyGen.LoadPublicKey(domain, "ksk")
			if err == nil {
				dsRecords[domain] = FormatDSRecordsFromKey(domain, ksk)
			}
		}
	}

	// Run validation if requested via query parameter (bounded + cached, R-043).
	var validation map[string]*ValidationResult
	if r.URL.Query().Get("validate") == "true" {
		v := NewValidator(cfg, state, cfg.Validation.Resolver, cfg.Validation.Timeout.Duration)
		if valOutput := cachedValidateAll(v); valOutput != nil {
			validation = valOutput.Zones
		}
	}

	// The template renders no secret-bearing config fields, so the full *Config
	// (which holds the Dynadot api_key/api_secret and heartbeat api_key) is
	// deliberately NOT passed to the template — only the data the dashboard
	// actually needs (R-067).
	data := struct {
		Status     *StatusOutput
		DSRecords  map[string]string
		Validation map[string]*ValidationResult
	}{
		Status:     status,
		DSRecords:  dsRecords,
		Validation: validation,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTemplate.Execute(w, data); err != nil {
		slog.Error("[WEB] Failed to execute template", "error", err)
	}
}

func apiStatusHandler(w http.ResponseWriter, r *http.Request, state *State) {
	w.Header().Set("Content-Type", "application/json")

	data, err := state.ToJSON()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(data); err != nil {
		slog.Debug("[WEB] Failed to write response", "error", err)
	}
}

func apiZoneHandler(w http.ResponseWriter, r *http.Request, cfg *Config, state *State) {
	// Extract domain from path: /api/zone/{domain}
	domain := strings.TrimPrefix(r.URL.Path, "/api/zone/")
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}

	// Deep copy — this handler runs concurrently with the signing loop,
	// which mutates the live ZoneState in place.
	zoneState := state.GetZoneCopy(domain)
	if zoneState == nil {
		http.Error(w, "Zone not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// Build detailed zone response
	response := struct {
		Domain    string     `json:"domain"`
		Status    string     `json:"status"`
		Zone      *ZoneState `json:"zone"`
		DSRecords string     `json:"ds_records,omitempty"`
	}{
		Domain: domain,
		Status: zoneState.Status(),
		Zone:   zoneState,
	}

	// Try to get DS records if KSK exists
	if zoneState.KSK != nil {
		keyGen := NewKeyGenerator(cfg)
		ksk, err := keyGen.LoadPublicKey(domain, "ksk")
		if err == nil {
			response.DSRecords = FormatDSRecordsFromKey(domain, ksk)
		}
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Debug("[WEB] Failed to encode response", "error", err)
	}
}

func apiValidateHandler(w http.ResponseWriter, r *http.Request, cfg *Config, state *State) {
	v := NewValidator(cfg, state, cfg.Validation.Resolver, cfg.Validation.Timeout.Duration)
	output := cachedValidateAll(v) // bounded + cached (R-043)
	if output == nil {
		// Cold start still running past the wait budget — tell the client to retry
		// rather than block the handler or emit a null body.
		w.Header().Set("Retry-After", "5")
		http.Error(w, "validation in progress, retry shortly", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(output); err != nil {
		slog.Debug("[WEB] Failed to encode validation response", "error", err)
	}
}

func apiValidateZoneHandler(w http.ResponseWriter, r *http.Request, cfg *Config, state *State) {
	domain := strings.TrimPrefix(r.URL.Path, "/api/validate/")
	if domain == "" {
		http.Error(w, "Domain required", http.StatusBadRequest)
		return
	}

	if state.GetZone(domain) == nil {
		http.Error(w, "Zone not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	v := NewValidator(cfg, state, cfg.Validation.Resolver, cfg.Validation.Timeout.Duration)
	result := v.ValidateZone(domain)

	if err := json.NewEncoder(w).Encode(result); err != nil {
		slog.Debug("[WEB] Failed to encode validation response", "error", err)
	}
}
