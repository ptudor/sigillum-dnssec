package signer

// SetAfterSourceRead installs the test-only seam that runs between reading a
// zone file's bytes and the post-read consistency check (see
// readSourceSnapshot). It exists so the root package's tests can simulate a
// producer racing the read; production code never calls it.
func SetAfterSourceRead(s *Signer, fn func(path string)) {
	s.afterSourceRead = fn
}
