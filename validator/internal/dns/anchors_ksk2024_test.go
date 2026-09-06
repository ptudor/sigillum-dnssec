package dns

import (
	"strings"
	"testing"
)

// The authoritative IANA DS digest of KSK-2024 (tag 38696), the pre-published
// successor root KSK. Authenticated by chaining from the already-pinned KSK-2017:
// recompute DS(20326) from the served root DNSKEY, confirm it equals the pinned
// constant, verify that key's RRSIG over the DNSKEY RRset, then derive this
// digest from the RRset so authenticated. Corroborated against four root servers,
// IANA's root-anchors.xml over HTTPS, and the deployed mirror.
const realKSK2024Digest = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"

// The successor KSK must be pinned, and pinned to its authentic digest.
func TestIsPinnedRootAnchor_KSK2024(t *testing.T) {
	if !IsPinnedRootAnchor(Anchor{KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: realKSK2024Digest}) {
		t.Error("KSK-2024 (38696) must be pinned so the 2026-10-11 rollover is a non-event")
	}
	if !IsPinnedRootAnchor(Anchor{KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: strings.ToLower(realKSK2024Digest)}) {
		t.Error("digest comparison must stay case-insensitive")
	}
}

// Pinning the successor must not weaken the R-024 gate: an attacker who knows the
// successor's key tag still cannot introduce their own digest under it.
func TestIsPinnedRootAnchor_KSK2024_RejectsWrongDigest(t *testing.T) {
	bad := []Anchor{
		{KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: strings.Repeat("A", 64)}, // attacker digest
		{KeyTag: 38696, Algorithm: 13, DigestType: 2, Digest: realKSK2024Digest},      // wrong algorithm
		{KeyTag: 38696, Algorithm: 8, DigestType: 1, Digest: strings.Repeat("A", 40)}, // wrong digest type
		{KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest},       // other KSK's digest
		{KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2024Digest},       // digests not interchangeable
	}
	for i, a := range bad {
		if IsPinnedRootAnchor(a) {
			t.Errorf("case %d must not be treated as pinned", i)
		}
	}
}

// The point of the whole change: after the 2026-10-11 rollover the anchor file
// stops carrying KSK-2017, and a build pinning only KSK-2017 would reject the
// authentic file wholesale and serve 503s. A file carrying only KSK-2024 must load.
func TestLoadAnchors_SurvivesKSK2017Retirement(t *testing.T) {
	postRollover := &RootAnchors{Zone: ".", Anchors: []Anchor{{
		ID: "KSK-2024", KeyTag: 38696, Algorithm: 8, DigestType: 2,
		Digest: realKSK2024Digest, ValidFrom: "2024-07-18T00:00:00Z",
	}}}
	got, err := LoadAnchors(writeAnchorFile(t, postRollover))
	if err != nil {
		t.Fatalf("a post-rollover file carrying only KSK-2024 must load: %v", err)
	}
	if len(got.Anchors) != 1 || got.Anchors[0].KeyTag != 38696 {
		t.Fatalf("anchors = %+v, want the single KSK-2024 record", got.Anchors)
	}
}

// Both KSKs present — the state during the overlap, and what the mirror serves today.
func TestLoadAnchors_AcceptsBothPinnedKSKs(t *testing.T) {
	overlap := &RootAnchors{Zone: ".", Anchors: []Anchor{
		{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z"},
		{ID: "KSK-2024", KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: realKSK2024Digest, ValidFrom: "2024-07-18T00:00:00Z"},
	}}
	got, err := LoadAnchors(writeAnchorFile(t, overlap))
	if err != nil {
		t.Fatalf("overlap file with both pinned KSKs must load: %v", err)
	}
	if len(got.Anchors) != 2 {
		t.Fatalf("got %d anchors, want both", len(got.Anchors))
	}
}

// A wholesale swap is still refused even though two tags are now pinned.
func TestLoadAnchors_StillRejectsWholesaleSwap(t *testing.T) {
	swap := &RootAnchors{Zone: ".", Anchors: []Anchor{
		{ID: "fake-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: strings.Repeat("A", 64), ValidFrom: "2017-02-02T00:00:00Z"},
		{ID: "fake-2024", KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: strings.Repeat("B", 64), ValidFrom: "2024-07-18T00:00:00Z"},
	}}
	if _, err := LoadAnchors(writeAnchorFile(t, swap)); err == nil {
		t.Fatal("an anchor set matching pinned tags but no pinned digest must be rejected")
	}
}
