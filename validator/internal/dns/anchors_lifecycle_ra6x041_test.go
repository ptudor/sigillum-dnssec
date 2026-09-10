package dns

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RA6X-041 (Medium): a load succeeds only with a currently usable pinned
// anchor; unusable files fall back to the URL; future anchors ride along.

func anchorJSON(t *testing.T, anchors ...Anchor) string {
	t.Helper()
	ra := &RootAnchors{Zone: ".", Anchors: anchors}
	return writeAnchorFile(t, ra)
}

func TestRA6X041_UnusableDocumentsFailToLoad(t *testing.T) {
	past := "2000-01-01T00:00:00Z"
	future := "2999-01-01T00:00:00Z"
	cases := map[string][]Anchor{
		"future-only":    {{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: future}},
		"malformed-date": {{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: "yesterday"}},
		"missing-date":   {{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest}},
		"expired-only":   {{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z", ValidUntil: &past}},
		"empty":          {},
	}
	for name, anchors := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadAnchors(anchorJSON(t, anchors...)); err == nil {
				t.Fatalf("%s document must not load successfully", name)
			}
		})
	}
	// A mixed active/future set loads and keeps the future anchor for rollover.
	got, err := LoadAnchors(anchorJSON(t,
		Anchor{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z"},
		Anchor{ID: "KSK-2024", KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: realKSK2024Digest, ValidFrom: future},
	))
	if err != nil {
		t.Fatalf("mixed active/future set must load: %v", err)
	}
	if len(got.Anchors) != 2 || len(GetActivePinnedAnchors(got)) != 1 {
		t.Fatalf("mixed set: %d anchors, %d active; want 2 and 1", len(got.Anchors), len(GetActivePinnedAnchors(got)))
	}
}

func TestRA6X041_UnusableFileFallsBackToURL(t *testing.T) {
	// Behind the operator file sits the built-in document (RDAYBLUEX-011);
	// disable it so the URL fallback under test is reached.
	t.Cleanup(SetEmbeddedAnchorsForTest([]byte(`{"zone":".","anchors":[]}`)))
	future := "2999-01-01T00:00:00Z"
	good := `{"zone":".","anchors":[{"id":"KSK-2017","keyTag":20326,"algorithm":8,"digestType":2,"digest":"` + realKSK2017Digest + `","validFrom":"2017-02-02T00:00:00Z"}]}`
	empty := `{"zone":".","anchors":[]}`
	var serve string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(serve))
	}))
	defer srv.Close()

	futureFile := anchorJSON(t, Anchor{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: future})
	serve = good
	got, err := LoadAnchorsWithFallback(futureFile, srv.URL)
	if err != nil || got.LoadedFrom != srv.URL {
		t.Fatalf("future-only file must fall back to the URL: got=%+v err=%v", got, err)
	}
	serve = empty
	if _, err := LoadAnchorsWithFallback(futureFile, srv.URL); err == nil {
		t.Fatal("an empty URL document must not count as a successful load")
	} else if !strings.Contains(err.Error(), "file") || !strings.Contains(err.Error(), "URL") {
		t.Fatalf("both failures must be named: %v", err)
	}
	// A usable file is preferred and the URL is not consulted.
	goodFile := filepath.Join(t.TempDir(), "good.json")
	if err := os.WriteFile(goodFile, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	serve = "not json"
	if got, err := LoadAnchorsWithFallback(goodFile, srv.URL); err != nil || got.LoadedFrom != goodFile {
		t.Fatalf("usable file must be used without the URL: got=%+v err=%v", got, err)
	}
}
