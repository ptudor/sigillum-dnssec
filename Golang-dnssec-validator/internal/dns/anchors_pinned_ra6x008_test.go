package dns

import (
	"strings"
	"testing"
)

// RA6X-008: the anchor set handed to root authentication must contain only
// currently-active, exactly pinned anchors. A loaded document may carry other
// entries as diagnostics, but GetActivePinnedAnchors must drop them.
func TestRA6X008_GetActivePinnedAnchors(t *testing.T) {
	future := "2999-01-01T00:00:00Z"
	past := "2000-01-01T00:00:00Z"
	set := &RootAnchors{Zone: ".", Anchors: []Anchor{
		{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z"},
		{ID: "KSK-2024", KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: realKSK2024Digest, ValidFrom: "2024-07-18T00:00:00Z"},
		{ID: "attacker", KeyTag: 4242, Algorithm: 13, DigestType: 2, Digest: strings.Repeat("C", 64), ValidFrom: "2017-02-02T00:00:00Z"},
		{ID: "attacker-2017-tag", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: strings.Repeat("D", 64), ValidFrom: "2017-02-02T00:00:00Z"},
		{ID: "future-pinned", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: future},
		{ID: "expired-pinned", KeyTag: 38696, Algorithm: 8, DigestType: 2, Digest: realKSK2024Digest, ValidFrom: "2024-07-18T00:00:00Z", ValidUntil: &past},
	}}

	got := GetActivePinnedAnchors(set)
	if len(got) != 2 {
		t.Fatalf("active pinned anchors = %+v, want exactly the two shipped pins", got)
	}
	for _, a := range got {
		if !IsPinnedRootAnchor(a) {
			t.Fatalf("unpinned anchor %q leaked into the active pinned set", a.ID)
		}
		if a.ID != "KSK-2017" && a.ID != "KSK-2024" {
			t.Fatalf("unexpected anchor %q in the active pinned set", a.ID)
		}
	}

	// The unfiltered active set still exposes the diagnostics.
	if n := len(GetActiveAnchors(set)); n != 4 {
		t.Fatalf("GetActiveAnchors = %d entries, want 4 (diagnostic entries retained)", n)
	}

	if got := GetActivePinnedAnchors(nil); got != nil && len(got) != 0 {
		t.Fatalf("nil set must yield no anchors, got %+v", got)
	}
}
