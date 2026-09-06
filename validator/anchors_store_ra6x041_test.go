package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

const ra6x041KSK2017 = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

// RA6X-041: a failed refresh keeps the last-known-good set and its load time.
func TestRA6X041_FailedRefreshRetainsLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "anchors.json")
	good := `{"zone":".","anchors":[{"id":"KSK-2017","keyTag":20326,"algorithm":8,"digestType":2,"digest":"` + ra6x041KSK2017 + `","validFrom":"2017-02-02T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"zone":".","anchors":[]}`)) // unusable fallback
	}))
	defer srv.Close()

	store := NewAnchorsStore(path, srv.URL)
	if err := store.Load(); err != nil {
		t.Fatalf("initial load: %v", err)
	}
	loadedAt := store.LoadedAt()
	if len(dns.GetActivePinnedAnchors(store.Get())) != 1 {
		t.Fatal("expected one active pinned anchor after the initial load")
	}

	// The mirror now serves a future-only document: the refresh must fail and
	// leave the working set and its timestamp untouched.
	future := `{"zone":".","anchors":[{"id":"KSK-2017","keyTag":20326,"algorithm":8,"digestType":2,"digest":"` + ra6x041KSK2017 + `","validFrom":"2999-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := store.Load(); err == nil {
		t.Fatal("refresh from an unusable file with an unusable fallback must fail")
	}
	if !store.LoadedAt().Equal(loadedAt) {
		t.Fatal("a failed refresh must not reset the successful-load timestamp")
	}
	if len(dns.GetActivePinnedAnchors(store.Get())) != 1 {
		t.Fatal("the last-known-good set must still be served")
	}
}
