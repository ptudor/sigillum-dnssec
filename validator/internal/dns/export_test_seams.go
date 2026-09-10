package dns

// SetEmbeddedAnchorsForTest replaces the built-in anchor document so tests
// can exercise the cache and URL stages behind it (or a broken build). It
// returns the function that restores the real document. Production code
// never calls it.
func SetEmbeddedAnchorsForTest(doc []byte) (restore func()) {
	prev := embeddedAnchorsDocument
	embeddedAnchorsDocument = doc
	return func() { embeddedAnchorsDocument = prev }
}
