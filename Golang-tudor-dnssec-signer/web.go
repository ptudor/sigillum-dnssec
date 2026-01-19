package main

import (
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

// securityHeaders wraps a handler to add security headers to all responses
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next(w, r)
	}
}

// NewWebServer creates a new HTTP server for the web UI
func NewWebServer(cfg *Config, state *State) *http.Server {
	mux := http.NewServeMux()

	// Register handlers with security headers
	mux.HandleFunc("/", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		dashboardHandler(w, r, cfg, state)
	}))
	mux.HandleFunc("/api/status", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		apiStatusHandler(w, r, state)
	}))
	mux.HandleFunc("/api/zone/", securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		apiZoneHandler(w, r, cfg, state)
	}))

	// Health endpoints
	RegisterHealthHandlers(mux, state, cfg)

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

	tmpl, err := template.ParseFS(templateFS, "templates/index.html")
	if err != nil {
		slog.Error("[WEB] Failed to parse template", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	status := state.ToStatusOutput()

	data := struct {
		Config *Config
		Status *StatusOutput
	}{
		Config: cfg,
		Status: status,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
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

	zoneState := state.GetZone(domain)
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
		ksk, _, err := keyGen.LoadKeyPair(domain, "ksk")
		if err == nil {
			response.DSRecords = FormatDSRecordsFromKey(domain, ksk)
		}
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Debug("[WEB] Failed to encode response", "error", err)
	}
}
