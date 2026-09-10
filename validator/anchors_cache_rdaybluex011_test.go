package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// RDAYBLUEX-011: the anchor store keeps an offline last-known-good cache. A
// clean start without network has nothing and says so; a start after a
// successful fetch validates from the cache; no failed refresh, corrupt
// document or write failure ever replaces the previous good set or cache.

const (
	rdaybluex011KSK2017 = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
	rdaybluex011KSK2024 = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
)

func rdaybluex011Doc(id string, tag int, digest, validFrom string) string {
	return `{"zone":".","anchors":[{"id":"` + id + `","keyTag":` + itoa011(tag) + `,"algorithm":8,"digestType":2,"digest":"` + digest + `","validFrom":"` + validFrom + `"}]}`
}

func itoa011(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// anchorMirror is a controllable HTTPS-less mirror double; its URL is only
// ever handed to the store.
type anchorMirror struct {
	srv  *httptest.Server
	body string
	hits int
}

func newAnchorMirror(t *testing.T) *anchorMirror {
	t.Helper()
	m := &anchorMirror{}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits++
		_, _ = w.Write([]byte(m.body))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func readiness(store *AnchorsStore) string {
	return NewHealthChecker(store).Check(context.Background()).Checks["root_anchors"]
}

func TestRDAYBLUEX011_CleanStartOfflineHasNothing(t *testing.T) {
	dir := t.TempDir()
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	store := NewAnchorsStore(filepath.Join(dir, "operator.json"), url)
	store.SetCachePath(filepath.Join(dir, "cache.json"))
	if err := store.Load(); err == nil || !strings.Contains(err.Error(), "cache") {
		t.Fatalf("with no file, no cache and no network the load fails naming every source: %v", err)
	}
	if store.Get() != nil || readiness(store) != "unavailable" {
		t.Fatalf("nothing is served: %v / %s", store.Get(), readiness(store))
	}
	if _, err := os.Stat(filepath.Join(dir, "cache.json")); !os.IsNotExist(err) {
		t.Fatal("a failed load must not create a cache file")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("no partial files: %v", entries)
	}
}

func TestRDAYBLUEX011_FetchThenRestartOffline(t *testing.T) {
	dir := t.TempDir()
	operator := filepath.Join(dir, "operator.json")
	cache := filepath.Join(dir, "cache.json")
	mirror := newAnchorMirror(t)
	mirror.body = rdaybluex011Doc("KSK-2017", 20326, rdaybluex011KSK2017, "2017-02-02T00:00:00Z")

	store := NewAnchorsStore(operator, mirror.srv.URL)
	store.SetCachePath(cache)
	if err := store.Load(); err != nil {
		t.Fatalf("online load: %v", err)
	}
	if store.CacheError() != nil {
		t.Fatalf("cache write: %v", store.CacheError())
	}
	info, err := os.Stat(cache)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache must exist with mode 0600: %v %v", info, err)
	}
	if got, _ := os.ReadFile(cache); string(got) != mirror.body {
		t.Fatal("the cache holds exactly the fetched bytes")
	}
	if store.Get().LoadedFrom != mirror.srv.URL || readiness(store) != "available" {
		t.Fatalf("loaded from the URL and ready: %s / %s", store.Get().LoadedFrom, readiness(store))
	}

	// Restart with the network gone: the cache serves validation.
	mirror.srv.Close()
	restarted := NewAnchorsStore(operator, mirror.srv.URL)
	restarted.SetCachePath(cache)
	if err := restarted.Load(); err != nil {
		t.Fatalf("offline restart must load from the cache: %v", err)
	}
	if restarted.Get().LoadedFrom != cache || len(dns.GetActivePinnedAnchors(restarted.Get())) != 1 {
		t.Fatalf("loaded from %q with %d active pinned anchors", restarted.Get().LoadedFrom, len(dns.GetActivePinnedAnchors(restarted.Get())))
	}
	if readiness(restarted) != "available" {
		t.Fatalf("readiness offline: %s", readiness(restarted))
	}
	// A refresh with the network still gone keeps the set and the cache.
	before := restarted.LoadedAt()
	if err := restarted.Refresh(); err == nil {
		t.Fatal("a refresh without network fails")
	}
	if !restarted.LoadedAt().Equal(before) || restarted.Get().LoadedFrom != cache {
		t.Fatal("a failed refresh keeps the current set")
	}
	if got, _ := os.ReadFile(cache); string(got) != mirror.body {
		t.Fatal("a failed refresh keeps the cache")
	}
}

func TestRDAYBLUEX011_BadRefreshesNeverReplaceTheGoodSet(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache.json")
	mirror := newAnchorMirror(t)
	good := rdaybluex011Doc("KSK-2017", 20326, rdaybluex011KSK2017, "2017-02-02T00:00:00Z")
	mirror.body = good
	store := NewAnchorsStore(filepath.Join(dir, "operator.json"), mirror.srv.URL)
	store.SetCachePath(cache)
	if err := store.Load(); err != nil {
		t.Fatal(err)
	}
	loadedAt := store.LoadedAt()

	bad := map[string]string{
		"truncated":   good[:len(good)-20],
		"not json":    "<html>",
		"unpinned":    rdaybluex011Doc("X", 1, strings.Repeat("A", 64), "2017-02-02T00:00:00Z"),
		"future-only": rdaybluex011Doc("KSK-2017", 20326, rdaybluex011KSK2017, "2999-01-01T00:00:00Z"),
		"expired":     `{"zone":".","anchors":[{"id":"KSK-2017","keyTag":20326,"algorithm":8,"digestType":2,"digest":"` + rdaybluex011KSK2017 + `","validFrom":"2017-02-02T00:00:00Z","validUntil":"2018-01-01T00:00:00Z"}]}`,
		"empty":       `{"zone":".","anchors":[]}`,
		"oversized":   good + strings.Repeat(" ", dns.MaxAnchorDocumentBytes),
	}
	for name, body := range bad {
		mirror.body = body
		if err := store.Refresh(); err == nil {
			t.Fatalf("%s: the refresh must fail", name)
		}
		if got, _ := os.ReadFile(cache); string(got) != good {
			t.Fatalf("%s: the cache must be unchanged", name)
		}
		if !store.LoadedAt().Equal(loadedAt) || store.Get().LoadedFrom != mirror.srv.URL || len(dns.GetActivePinnedAnchors(store.Get())) != 1 {
			t.Fatalf("%s: the good set must be unchanged", name)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("no temporary files may remain: %v", entries)
	}

	// A good refresh replaces both the set and the cache.
	newer := rdaybluex011Doc("KSK-2024", 38696, rdaybluex011KSK2024, "2024-01-01T00:00:00Z")
	mirror.body = newer
	if err := store.Refresh(); err != nil {
		t.Fatalf("good refresh: %v", err)
	}
	if got, _ := os.ReadFile(cache); string(got) != newer {
		t.Fatal("a good refresh updates the cache")
	}
	if store.Get().Anchors[0].KeyTag != 38696 {
		t.Fatal("a good refresh updates the set")
	}
}

func TestRDAYBLUEX011_CacheWriteFailureDoesNotFailTheLoad(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	dir := t.TempDir()
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
	mirror := newAnchorMirror(t)
	mirror.body = rdaybluex011Doc("KSK-2017", 20326, rdaybluex011KSK2017, "2017-02-02T00:00:00Z")
	store := NewAnchorsStore(filepath.Join(dir, "operator.json"), mirror.srv.URL)
	store.SetCachePath(filepath.Join(ro, "cache.json"))
	if err := store.Load(); err != nil {
		t.Fatalf("the load succeeds from the URL: %v", err)
	}
	if store.CacheError() == nil {
		t.Fatal("the write failure is reported")
	}
	if store.Get() == nil || readiness(store) != "available" {
		t.Fatal("anchors are served despite the cache failure")
	}
	entries, _ := os.ReadDir(ro)
	if len(entries) != 0 {
		t.Fatalf("no partial files: %v", entries)
	}
}

func TestRDAYBLUEX011_OperatorFileTakesPrecedenceAndIsNeverCached(t *testing.T) {
	dir := t.TempDir()
	operator := filepath.Join(dir, "operator.json")
	cache := filepath.Join(dir, "cache.json")
	if err := os.WriteFile(operator, []byte(rdaybluex011Doc("KSK-2017", 20326, rdaybluex011KSK2017, "2017-02-02T00:00:00Z")), 0o600); err != nil {
		t.Fatal(err)
	}
	mirror := newAnchorMirror(t)
	mirror.body = "not json"
	store := NewAnchorsStore(operator, mirror.srv.URL)
	store.SetCachePath(cache)
	if err := store.Load(); err != nil || store.Get().LoadedFrom != operator {
		t.Fatalf("the operator file is used: %v", err)
	}
	if err := store.Refresh(); err != nil || store.Get().LoadedFrom != operator {
		t.Fatalf("refresh re-reads the operator file: %v", err)
	}
	if mirror.hits != 0 {
		t.Fatal("the URL is not consulted while the operator file is usable")
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatal("the operator file is never copied to the cache")
	}
	// Disabled cache: nothing is written even after a fetch.
	if err := os.Remove(operator); err != nil {
		t.Fatal(err)
	}
	mirror.body = rdaybluex011Doc("KSK-2017", 20326, rdaybluex011KSK2017, "2017-02-02T00:00:00Z")
	store.SetCachePath("")
	if err := store.Load(); err != nil || store.CacheError() != nil {
		t.Fatalf("fetch with the cache disabled: %v %v", err, store.CacheError())
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatal("a disabled cache is never written")
	}
}
