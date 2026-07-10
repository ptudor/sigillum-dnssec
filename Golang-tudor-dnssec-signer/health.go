package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// RegisterHealthHandlersWithDaemon registers health check endpoints with daemon
// liveness checks. The handlers resolve cfg/state per request via daemon.current()
// so they reflect a SIGHUP reload rather than the pointers captured at startup
// (R-006). daemon must be non-nil.
func RegisterHealthHandlersWithDaemon(mux *http.ServeMux, daemon *Daemon) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setSecurityHeaders(w)
		cfg, state := daemon.current()
		healthHandler(w, r, state, cfg, daemon)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setSecurityHeaders(w)
		cfg, state := daemon.current()
		healthzHandler(w, r, state, cfg, daemon)
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
func healthHandler(w http.ResponseWriter, r *http.Request, state *State, cfg *Config, daemon *Daemon) {
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

	// Check signing loop liveness
	signingLoopAlive := true
	if daemon != nil {
		if daemon.signingLoopDead.Load() {
			depErrors = append(depErrors, "signing_loop: goroutine has exited")
			healthy = false
			signingLoopAlive = false
		}
		lastRun := daemon.lastSigningRun.Load()
		if lastRun > 0 {
			staleness := time.Since(time.Unix(lastRun, 0))
			// If the signing loop hasn't run in 3x the poll interval, something is wrong
			if staleness > 3*cfg.PollInterval.Duration {
				depErrors = append(depErrors, fmt.Sprintf("signing_loop: last ran %s ago (expected every %s)", staleness.Round(time.Second), cfg.PollInterval.String()))
				healthy = false
				signingLoopAlive = false
			}
		}
	}

	// Check for expired signatures
	var expiredZones []string
	now := time.Now()
	for domain, zone := range status.Zones {
		if !zone.SignaturesExp.IsZero() && now.After(zone.SignaturesExp) {
			expiredZones = append(expiredZones, domain)
			healthy = false
		}
	}
	if len(expiredZones) > 0 {
		depErrors = append(depErrors, fmt.Sprintf("expired_signatures: %v", expiredZones))
	}

	w.Header().Set("Content-Type", "application/json")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	response := struct {
		Status           string        `json:"status"`
		Summary          StatusSummary `json:"summary"`
		SigningLoopAlive bool          `json:"signing_loop_alive"`
		ExpiredZones     []string      `json:"expired_zones,omitempty"`
		DepErrors        []string      `json:"dependency_errors,omitempty"`
	}{
		Status:           "healthy",
		Summary:          status.Summary,
		SigningLoopAlive: signingLoopAlive,
		ExpiredZones:     expiredZones,
		DepErrors:        depErrors,
	}

	if !healthy {
		response.Status = "unhealthy"
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Debug("[HEALTH] Failed to encode response", "error", err)
	}
}

// healthzHandler returns simple OK for kubernetes probes
func healthzHandler(w http.ResponseWriter, r *http.Request, state *State, cfg *Config, daemon *Daemon) {
	status := state.ToStatusOutput()
	healthy := status.Summary.Errors == 0

	// Check directory dependencies
	if err := checkDirWritable(cfg.OutputDir); err != nil {
		healthy = false
	}
	if err := checkDirWritable(cfg.DataDir); err != nil {
		healthy = false
	}

	// Check signing loop liveness
	if daemon != nil {
		if daemon.signingLoopDead.Load() {
			healthy = false
		}
		lastRun := daemon.lastSigningRun.Load()
		if lastRun > 0 && time.Since(time.Unix(lastRun, 0)) > 3*cfg.PollInterval.Duration {
			healthy = false
		}
	}

	// Check for expired signatures
	now := time.Now()
	for _, zone := range status.Zones {
		if !zone.SignaturesExp.IsZero() && now.After(zone.SignaturesExp) {
			healthy = false
			break
		}
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
