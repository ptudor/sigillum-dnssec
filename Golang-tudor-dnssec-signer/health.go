package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// RegisterHealthHandlers registers health check endpoints
func RegisterHealthHandlers(mux *http.ServeMux, state *State) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		healthHandler(w, r, state)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		healthzHandler(w, r, state)
	})
}

// healthHandler returns detailed health status
func healthHandler(w http.ResponseWriter, r *http.Request, state *State) {
	status := state.ToStatusOutput()

	// Check if any zones have errors
	healthy := status.Summary.Errors == 0

	w.Header().Set("Content-Type", "application/json")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	response := struct {
		Status  string        `json:"status"`
		Summary StatusSummary `json:"summary"`
	}{
		Status:  "healthy",
		Summary: status.Summary,
	}

	if !healthy {
		response.Status = "unhealthy"
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Debug("[HEALTH] Failed to encode response", "error", err)
	}
}

// healthzHandler returns simple OK for kubernetes probes
func healthzHandler(w http.ResponseWriter, r *http.Request, state *State) {
	status := state.ToStatusOutput()

	if status.Summary.Errors > 0 {
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
