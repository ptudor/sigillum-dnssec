package main

import (
	"encoding/json"
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

	json.NewEncoder(w).Encode(response)
}

// healthzHandler returns simple OK for kubernetes probes
func healthzHandler(w http.ResponseWriter, r *http.Request, state *State) {
	status := state.ToStatusOutput()

	if status.Summary.Errors > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("UNHEALTHY"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
