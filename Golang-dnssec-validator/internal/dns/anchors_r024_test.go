package dns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const realKSK2017Digest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

func writeAnchorFile(t *testing.T, a *RootAnchors) string {
	t.Helper()
	data, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "root-anchors.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// R-024: an attacker-supplied set that carries a dummy entry with a known root
// tag plus a malicious anchor must be rejected at load — the dummy entry's
// digest does not match the pinned authoritative digest, so no pinned anchor
// is present.
func TestLoadAnchors_RejectsDummyTagPlusMaliciousAnchor(t *testing.T) {
	swap := &RootAnchors{
		Zone: ".",
		Anchors: []Anchor{
			{ // dummy: real pinned tag, but attacker's digest (wrong)
				ID: "dummy-20326", KeyTag: 20326, Algorithm: 8, DigestType: 2,
				Digest:    strings.Repeat("A", 64),
				ValidFrom: "2017-02-02T00:00:00Z",
			},
			{ // attacker's own anchor
				ID: "attacker", KeyTag: 6666, Algorithm: 8, DigestType: 2,
				Digest:    strings.Repeat("B", 64),
				ValidFrom: "2017-02-02T00:00:00Z",
			},
		},
	}
	if _, err := LoadAnchors(writeAnchorFile(t, swap)); err == nil {
		t.Fatal("LoadAnchors must reject dummy-known-tag + malicious anchor (no pinned digest match)")
	}
}

// R-024: an anchor set carrying the authoritative pinned KSK-2017 record loads.
func TestLoadAnchors_AcceptsPinned(t *testing.T) {
	good := &RootAnchors{Zone: ".", Anchors: []Anchor{{
		ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2,
		Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z",
	}}}
	if _, err := LoadAnchors(writeAnchorFile(t, good)); err != nil {
		t.Fatalf("LoadAnchors should accept the pinned KSK-2017: %v", err)
	}
}

// R-024: structural validation rejects malformed digests and non-root zones.
func TestLoadAnchors_StructuralValidation(t *testing.T) {
	cases := map[string]*RootAnchors{
		"short digest": {Zone: ".", Anchors: []Anchor{{
			KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: "DEAD",
			ValidFrom: "2017-02-02T00:00:00Z",
		}}},
		"non-hex digest": {Zone: ".", Anchors: []Anchor{{
			KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: strings.Repeat("Z", 64),
			ValidFrom: "2017-02-02T00:00:00Z",
		}}},
		"unsupported digest type": {Zone: ".", Anchors: []Anchor{{
			KeyTag: 20326, Algorithm: 8, DigestType: 99, Digest: realKSK2017Digest,
			ValidFrom: "2017-02-02T00:00:00Z",
		}}},
		"wrong zone": {Zone: "example.com.", Anchors: []Anchor{{
			KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest,
			ValidFrom: "2017-02-02T00:00:00Z",
		}}},
	}
	for name, a := range cases {
		if _, err := LoadAnchors(writeAnchorFile(t, a)); err == nil {
			t.Errorf("%s: LoadAnchors should have rejected the set", name)
		}
	}
}

// R-024: duplicate (key tag, digest type) records are rejected.
func TestLoadAnchors_RejectsDuplicates(t *testing.T) {
	dup := &RootAnchors{Zone: ".", Anchors: []Anchor{
		{KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z"},
		{KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z"},
	}}
	if _, err := LoadAnchors(writeAnchorFile(t, dup)); err == nil {
		t.Fatal("LoadAnchors should reject duplicate anchors")
	}
}

// R-024: IsPinnedRootAnchor only accepts an exact authoritative match.
func TestIsPinnedRootAnchor(t *testing.T) {
	if !IsPinnedRootAnchor(Anchor{KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: strings.ToLower(realKSK2017Digest)}) {
		t.Error("pinned KSK-2017 (lowercase hex) should match")
	}
	bad := []Anchor{
		{KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: strings.Repeat("A", 64)}, // wrong digest
		{KeyTag: 20326, Algorithm: 13, DigestType: 2, Digest: realKSK2017Digest},      // wrong algorithm
		{KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest},       // successor not pinned
	}
	for i, a := range bad {
		if IsPinnedRootAnchor(a) {
			t.Errorf("case %d must not be treated as pinned", i)
		}
	}
}

// R-024: the anchor HTTP client rejects scheme-downgrade and cross-origin redirects.
func TestLoadAnchorsFromURL_RejectsUnsafeRedirect(t *testing.T) {
	// Cross-origin redirect: server A redirects to server B.
	good := &RootAnchors{Zone: ".", Anchors: []Anchor{{
		ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2,
		Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z",
	}}}
	data, _ := json.Marshal(good)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	if _, err := LoadAnchorsFromURL(redirector.URL); err == nil {
		t.Fatal("LoadAnchorsFromURL should refuse a cross-origin redirect")
	}
}
