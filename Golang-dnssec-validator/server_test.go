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

func TestIsCacheableStaticAsset(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{path: "/app.js", want: true},
		{path: "/style.css", want: true},
		{path: "/image.png", want: true},
		{path: "/index.html", want: false},
		{path: "/api/validate", want: false},
	}

	for _, tc := range cases {
		got := isCacheableStaticAsset(tc.path)
		if got != tc.want {
			t.Fatalf("isCacheableStaticAsset(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
