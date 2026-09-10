package dns

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RDAYBLUEX-011: the last-known-good anchor cache is written only with a
// document that would be accepted when read back, atomically, with private
// permissions, and never replaces the previous cache on failure.

const cacheGoodDoc = `{"zone":".","anchors":[{"id":"KSK-2017","keyTag":20326,"algorithm":8,"digestType":2,"digest":"` + realKSK2017Digest + `","validFrom":"2017-02-02T00:00:00Z"}]}`

func TestRDAYBLUEX011_WriteAnchorCacheIsAtomicPrivateAndValidated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root-anchors.json")
	if err := WriteAnchorCache(path, []byte(cacheGoodDoc)); err != nil {
		t.Fatalf("a usable document is cached: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache mode %o, want 0600", info.Mode().Perm())
	}
	if got, _ := os.ReadFile(path); string(got) != cacheGoodDoc {
		t.Fatal("the cache holds exactly the validated bytes")
	}
	if a, err := LoadAnchors(path); err != nil || len(GetActivePinnedAnchors(a)) != 1 {
		t.Fatalf("the cache loads as a usable set: %v", err)
	}

	rejected := map[string]string{
		"truncated":   cacheGoodDoc[:len(cacheGoodDoc)/2],
		"not json":    "<html>",
		"unpinned":    `{"zone":".","anchors":[{"id":"X","keyTag":1,"algorithm":8,"digestType":2,"digest":"` + strings.Repeat("A", 64) + `","validFrom":"2017-02-02T00:00:00Z"}]}`,
		"future-only": `{"zone":".","anchors":[{"id":"KSK-2017","keyTag":20326,"algorithm":8,"digestType":2,"digest":"` + realKSK2017Digest + `","validFrom":"2999-01-01T00:00:00Z"}]}`,
		"empty":       `{"zone":".","anchors":[]}`,
		"oversized":   cacheGoodDoc + strings.Repeat(" ", MaxAnchorDocumentBytes),
	}
	for name, doc := range rejected {
		if err := WriteAnchorCache(path, []byte(doc)); err == nil {
			t.Fatalf("%s document must not be cached", name)
		}
		if got, _ := os.ReadFile(path); string(got) != cacheGoodDoc {
			t.Fatalf("%s: the previous cache must survive a refused write", name)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("no temporary files may be left behind: %v", entries)
	}

	// A write failure (unwritable directory) leaves the previous cache and
	// no temporary file.
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := WriteAnchorCache(path, []byte(cacheGoodDoc)); err == nil {
		t.Fatal("an unwritable directory is a write error")
	}
	if got, _ := os.ReadFile(path); string(got) != cacheGoodDoc {
		t.Fatal("the previous cache must survive a failed write")
	}
	if err := WriteAnchorCache("", []byte(cacheGoodDoc)); err == nil {
		t.Fatal("an empty path is refused")
	}
}

func TestRDAYBLUEX011_LoadOrderFileCacheURL(t *testing.T) {
	// An unusable built-in document, so the cache and URL stages are reached.
	t.Cleanup(SetEmbeddedAnchorsForTest([]byte(`{"zone":".","anchors":[]}`)))
	dir := t.TempDir()
	file := filepath.Join(dir, "operator.json")
	cache := filepath.Join(dir, "cache.json")
	hits := 0
	var serve string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(serve))
	}))
	defer srv.Close()

	// Nothing local: the URL is fetched and its bytes returned for caching.
	serve = cacheGoodDoc
	a, data, err := LoadAnchorsWithCache(file, cache, srv.URL)
	if err != nil || a.LoadedFrom != srv.URL || string(data) != cacheGoodDoc {
		t.Fatalf("URL fallback: %+v %q %v", a, data, err)
	}
	if err := WriteAnchorCache(cache, data); err != nil {
		t.Fatal(err)
	}
	// The cache is preferred before the network and no bytes are returned.
	serve = "not json"
	hitsBefore := hits
	a, data, err = LoadAnchorsWithCache(file, cache, srv.URL)
	if err != nil || a.LoadedFrom != cache || data != nil || hits != hitsBefore {
		t.Fatalf("cache must be used without the URL: %+v %v hits=%d", a, err, hits-hitsBefore)
	}
	// The operator's file wins over both.
	other := `{"zone":".","anchors":[{"id":"KSK-2024","keyTag":38696,"algorithm":8,"digestType":2,"digest":"` + realKSK2024Digest + `","validFrom":"2024-01-01T00:00:00Z"}]}`
	if err := os.WriteFile(file, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	a, data, err = LoadAnchorsWithCache(file, cache, srv.URL)
	if err != nil || a.LoadedFrom != file || data != nil {
		t.Fatalf("operator file precedence: %+v %v", a, err)
	}
	// A corrupt cache falls through to the URL; when that fails too the
	// error names every source.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadAnchorsWithCache(file, cache, srv.URL); err == nil ||
		!strings.Contains(err.Error(), "cache") || !strings.Contains(err.Error(), "URL") || !strings.Contains(err.Error(), "file") || !strings.Contains(err.Error(), "built-in") {
		t.Fatalf("all four sources must be named: %v", err)
	}
	// An empty cache path disables the stage.
	serve = cacheGoodDoc
	a, data, err = LoadAnchorsWithCache(file, "", srv.URL)
	if err != nil || a.LoadedFrom != srv.URL || data == nil {
		t.Fatalf("no cache stage: %+v %v", a, err)
	}
}
