package dns

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RDAYBLUEX-011 (built-in document): the binary ships a reviewed anchor
// document whose unexpired anchors are exactly pinned, it is used before the
// URL, and a fresh installation with no file, no cache and no network still
// establishes root trust.

func TestRDAYBLUEX011_EmbeddedAnchorsArePinnedAndUsable(t *testing.T) {
	a, err := LoadEmbeddedAnchors()
	if err != nil {
		t.Fatalf("the built-in document must load: %v", err)
	}
	if a.LoadedFrom != EmbeddedAnchorsSource || a.Zone != "." {
		t.Fatalf("loaded_from %q zone %q", a.LoadedFrom, a.Zone)
	}
	active := GetActivePinnedAnchors(a)
	if len(active) == 0 {
		t.Fatal("the built-in document must carry a currently active pinned anchor")
	}
	// Every anchor that survives finalization (unexpired) must be pinned:
	// the document may not smuggle a root of trust the pins do not name.
	for _, anchor := range a.Anchors {
		if !IsPinnedRootAnchor(anchor) {
			t.Fatalf("built-in anchor %q (tag %d) is not pinned", anchor.ID, anchor.KeyTag)
		}
	}
	// And the currently pinned keys are all present, so a pin without a
	// shipped anchor cannot happen silently.
	for _, p := range pinnedRootAnchors {
		found := false
		for _, anchor := range a.Anchors {
			if anchor.KeyTag == p.KeyTag && IsPinnedRootAnchor(anchor) {
				found = true
			}
		}
		if !found {
			t.Fatalf("pinned key tag %d has no anchor in the built-in document", p.KeyTag)
		}
	}
	// The dates parse and the active set is stable for the foreseeable
	// future (no validUntil on the live keys).
	for _, anchor := range active {
		if anchor.ValidUntil != nil {
			t.Fatalf("active built-in anchor %q has a validUntil; the document would silently expire", anchor.ID)
		}
		if _, err := time.Parse(time.RFC3339, anchor.ValidFrom); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRDAYBLUEX011_BuiltInIsUsedBeforeTheURL(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(cacheGoodDoc))
	}))
	defer srv.Close()
	dir := t.TempDir()
	a, data, err := LoadAnchorsWithCache(filepath.Join(dir, "missing.json"), filepath.Join(dir, "cache.json"), srv.URL)
	if err != nil || a.LoadedFrom != EmbeddedAnchorsSource || data != nil {
		t.Fatalf("no file and no cache must load the built-in document: %+v %v", a, err)
	}
	if hits != 0 {
		t.Fatal("the URL must not be contacted while the built-in document is usable")
	}
	if len(GetActivePinnedAnchors(a)) == 0 {
		t.Fatal("the built-in document establishes root trust")
	}
	// An operator file still wins over the built-in document.
	file := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(file, []byte(cacheGoodDoc), 0o600); err != nil {
		t.Fatal(err)
	}
	a, _, err = LoadAnchorsWithCache(file, "", srv.URL)
	if err != nil || a.LoadedFrom != file {
		t.Fatalf("operator file precedence: %+v %v", a, err)
	}
	// Only when the built-in document is unusable is the URL consulted.
	t.Cleanup(SetEmbeddedAnchorsForTest([]byte(`{"zone":".","anchors":[]}`)))
	a, data, err = LoadAnchorsWithCache(filepath.Join(dir, "missing.json"), "", srv.URL)
	if err != nil || a.LoadedFrom != srv.URL || data == nil || hits != 1 {
		t.Fatalf("URL is the last resort: %+v %v hits=%d", a, err, hits)
	}
}
