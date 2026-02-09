package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

// RegisterHealthHandlers registers health check endpoints
func RegisterHealthHandlers(mux *http.ServeMux, state *State, cfg *Config) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setSecurityHeaders(w)
		healthHandler(w, r, state, cfg)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setSecurityHeaders(w)
		healthzHandler(w, r, state, cfg)
	})
}

// setSecurityHeaders adds standard security headers to responses
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

// healthHandler returns detailed health status
func healthHandler(w http.ResponseWriter, r *http.Request, state *State, cfg *Config) {
	status := state.ToStatusOutput()

	// Check if any zones have errors
	healthy := status.Summary.Errors == 0

	// Check directory dependencies
	var depErrors []string
	if err := checkDirWritable(cfg.OutputDir); err != nil {
		depErrors = append(depErrors, "output_dir: "+err.Error())
		healthy = false
	}
	if err := checkDirWritable(cfg.DataDir); err != nil {
		depErrors = append(depErrors, "data_dir: "+err.Error())
		healthy = false
	}
	if err := checkDirWritable(cfg.KeysDir()); err != nil {
		depErrors = append(depErrors, "keys_dir: "+err.Error())
		healthy = false
	}

	w.Header().Set("Content-Type", "application/json")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	response := struct {
		Status    string        `json:"status"`
		Summary   StatusSummary `json:"summary"`
		DepErrors []string      `json:"dependency_errors,omitempty"`
	}{
		Status:    "healthy",
		Summary:   status.Summary,
		DepErrors: depErrors,
	}

	if !healthy {
		response.Status = "unhealthy"
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Debug("[HEALTH] Failed to encode response", "error", err)
	}
}

// healthzHandler returns simple OK for kubernetes probes
func healthzHandler(w http.ResponseWriter, r *http.Request, state *State, cfg *Config) {
	status := state.ToStatusOutput()
	healthy := status.Summary.Errors == 0

	// Check directory dependencies
	if err := checkDirWritable(cfg.OutputDir); err != nil {
		healthy = false
	}
	if err := checkDirWritable(cfg.DataDir); err != nil {
		healthy = false
	}

	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte("UNHEALTHY")); err != nil {
			slog.Debug("[HEALTH] Failed to write response", "error", err)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		slog.Debug("[HEALTH] Failed to write response", "error", err)
	}
}

// checkDirWritable verifies a directory exists and appears writable by
// checking stat and permission bits. This avoids creating temp files on
// every health probe, keeping checks non-destructive and fast.
func checkDirWritable(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	// Check owner-write bit as a heuristic — this covers the common case
	// where the daemon runs as the directory owner.
	if info.Mode().Perm()&0200 == 0 {
		return fmt.Errorf("%s is not writable", dir)
	}
	return nil
}
