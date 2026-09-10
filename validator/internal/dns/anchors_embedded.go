package dns

import _ "embed"

// embeddedRootAnchors is the release-reviewed root trust anchor document
// shipped inside the binary (RDAYBLUEX-011, the "ship a reviewed document"
// option, added 2026-09-10 alongside the last-known-good cache). It is the
// mirror's JSON rendering of IANA's root-anchors.xml: every unexpired anchor
// it lists is one of pinnedRootAnchors, so it can establish root trust
// without any network access, and a fresh installation never has to fetch
// the document from the URL — the one moment an interposed network could
// try to shape what the validator loads. Updating it is a reviewed code
// change, exactly like updating a pin; the tests refuse a document whose
// unexpired anchors are not all pinned.
//
//go:embed root-anchors.json
var embeddedRootAnchors []byte

// embeddedAnchorsDocument is what LoadEmbeddedAnchors parses; a test seam
// (SetEmbeddedAnchorsForTest) so the cache and URL stages can be exercised.
var embeddedAnchorsDocument = embeddedRootAnchors

// EmbeddedAnchorsSource is the LoadedFrom value of the built-in document.
const EmbeddedAnchorsSource = "built-in"

// LoadEmbeddedAnchors parses and validates the built-in anchor document
// through the same pipeline as every other source.
func LoadEmbeddedAnchors() (*RootAnchors, error) {
	return ParseAnchors(embeddedAnchorsDocument, EmbeddedAnchorsSource)
}
