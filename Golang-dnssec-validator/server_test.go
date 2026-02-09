package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWithWriteDeadlinePassthrough(t *testing.T) {
	handler := withWriteDeadline(time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}
