package fsutil

// SetSyncDirForTest installs the test-only directory-fsync seam used by the
// atomic writers and returns the function that restores the previous one. It
// exists so tests outside this package can exercise the post-rename
// durability contract (RA6X-049): a sync that fails after a visible rename
// surfaces as a *DurabilityError. Production code never calls it.
func SetSyncDirForTest(fn func(dir string) error) (restore func()) {
	prev := syncDirFn
	syncDirFn = fn
	return func() { syncDirFn = prev }
}
