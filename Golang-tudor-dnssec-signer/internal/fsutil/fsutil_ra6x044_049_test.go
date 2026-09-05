package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// withOwnership activates ownership transfer for the test with the given chown
// implementation and restores the package state afterwards.
func withOwnership(t *testing.T, active bool, chown func(string, int, int) error) {
	t.Helper()
	prevOwn, prevChown, prevEuid := ownership.active, chownFn, geteuid
	ownership.active = active
	ownership.uid, ownership.gid = 1234, 1234
	chownFn = chown
	t.Cleanup(func() {
		ownership.active = prevOwn
		chownFn = prevChown
		geteuid = prevEuid
	})
}

// RA6X-044: a failed ownership assignment is a failed write. The readable
// predecessor must survive and no staged file may be left behind.
func TestRA6X044_ChownFailureAbortsBeforeReplacing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	withOwnership(t, true, func(string, int, int) error { return errors.New("EPERM injected") })

	err := WriteFileAtomicOwned(path, []byte("new"), 0o600)
	if err == nil || !strings.Contains(err.Error(), "predecessor left in place") {
		t.Fatalf("chown failure must abort with a specific error, got %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != "old" {
		t.Fatalf("predecessor must be untouched, got %q", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("no staged temp file may remain, dir has %d entries", len(entries))
	}
	// CopyFile follows the same contract.
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CopyFile(src, filepath.Join(dir, "dst")); err == nil {
		t.Fatal("CopyFile must fail when ownership cannot be assigned")
	}
	if _, err := os.Stat(filepath.Join(dir, "dst")); err == nil {
		t.Fatal("CopyFile must not leave a destination it could not own")
	}
	// With a working chown the write succeeds and the chown target is used.
	var seen string
	withOwnership(t, true, func(p string, uid, gid int) error { seen = p; return nil })
	if err := WriteFileAtomicOwned(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("write with working chown: %v", err)
	}
	if !strings.Contains(seen, ".state.json.") {
		t.Fatalf("ownership must be applied to the staged file before the rename, got %q", seen)
	}
	if got, _ := os.ReadFile(path); string(got) != "new" {
		t.Fatal("replacement not visible")
	}
}

// RA6X-044: InitOwnershipTarget distinguishes a missing target from a failed
// inspection and from an applicable target.
func TestRA6X044_InitOwnershipTargetOutcomes(t *testing.T) {
	withOwnership(t, false, os.Chown)
	geteuid = func() int { return 0 } // pretend to be root

	dir := t.TempDir()
	status, err := InitOwnershipTarget(filepath.Join(dir, "missing"))
	if err != nil || status != OwnershipTargetMissing {
		t.Fatalf("missing target: status=%v err=%v", status, err)
	}
	if ownership.active {
		t.Fatal("a missing target must not activate ownership transfer")
	}

	// An unreadable parent makes the inspection FAIL rather than silently no-op.
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	if os.Geteuid() != 0 { // real root can traverse a 0000 directory
		if _, err := InitOwnershipTarget(filepath.Join(locked, "data")); err == nil {
			t.Fatal("an inspection failure must be an error")
		}
	}

	// The test's own directory is not root-owned, so it is an applicable target.
	status, err = InitOwnershipTarget(dir)
	if err != nil || status != OwnershipActive || !ownership.active {
		t.Fatalf("applicable target: status=%v err=%v active=%v", status, err, ownership.active)
	}
	if !strings.Contains(BootstrapInstructions("/var/lib/x"), "install -d") {
		t.Fatal("bootstrap instructions must name the explicit procedure")
	}

	// Non-root: inactive regardless.
	geteuid = func() int { return 1000 }
	ownership.active = false
	if status, err := InitOwnershipTarget(dir); err != nil || status != OwnershipInactive {
		t.Fatalf("non-root: status=%v err=%v", status, err)
	}
}

// RA6X-049: a directory-sync failure after the rename is reported as a
// visible-but-durability-uncertain commit, distinct from pre-rename failures,
// and unsupported directory fsync is classified as harmless.
func TestRA6X049_DurabilityOutcomes(t *testing.T) {
	var d *DurabilityError
	err := &DurabilityError{Path: "/x", Err: syscall.EIO}
	if !IsCommitted(err) || !errors.As(err, &d) || !errors.Is(err, syscall.EIO) {
		t.Fatal("DurabilityError must be detectable and unwrap its cause")
	}
	if IsCommitted(errors.New("pre-rename failure")) {
		t.Fatal("an ordinary error is not a committed write")
	}
	for _, e := range []error{syscall.EINVAL, syscall.ENOTSUP, syscall.EOPNOTSUPP} {
		if !dirSyncUnsupported(e) {
			t.Fatalf("%v must be classified as unsupported directory fsync", e)
		}
	}
	for _, e := range []error{syscall.EIO, syscall.EACCES, syscall.EROFS} {
		if dirSyncUnsupported(e) {
			t.Fatalf("%v must NOT be classified as harmless", e)
		}
	}
	// SyncDir on a missing directory is an error, not silence.
	if err := SyncDir(filepath.Join(t.TempDir(), "gone")); err == nil {
		t.Fatal("SyncDir must report an unopenable directory")
	}
	// A normal directory syncs (or is classified unsupported) without error.
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("SyncDir on a temp dir: %v", err)
	}
}

// withFailingDirSync makes every directory fsync fail with err for the test.
func withFailingDirSync(t *testing.T, err error) {
	t.Helper()
	prev := syncDirFn
	syncDirFn = func(string) error { return err }
	t.Cleanup(func() { syncDirFn = prev })
}

// RA6X-049 at the write helpers, not just the helper types: a directory fsync
// that fails AFTER the rename must leave the new bytes in place (the rename
// succeeded — that file is the current generation) and report the uncertainty
// as a *DurabilityError, so callers reconcile with the visible generation
// instead of rolling back a file that is already live.
//
// TestRA6X049_DurabilityOutcomes above covers the classification helpers; this
// covers the contract the callers actually depend on.
func TestRA6X049_WriteHelpersReportCommittedButUnsynced(t *testing.T) {
	withFailingDirSync(t, syscall.EIO)

	t.Run("WriteFileAtomicOwned", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "zone.signed")
		if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
			t.Fatal(err)
		}
		err := WriteFileAtomicOwned(path, []byte("new"), 0644)
		if err == nil {
			t.Fatal("a failed directory fsync must be reported, not discarded")
		}
		if !IsCommitted(err) {
			t.Fatalf("a post-rename sync failure must be a committed write, got %v", err)
		}
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got) != "new" {
			t.Fatalf("the replacement is visible and must be kept; file holds %q", got)
		}
		assertNoTempLeft(t, dir, "zone.signed")
	})

	t.Run("CopyFile", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src.key")
		dst := filepath.Join(dir, "dst.key")
		if err := os.WriteFile(src, []byte("material"), 0600); err != nil {
			t.Fatal(err)
		}
		err := CopyFile(src, dst)
		if err == nil {
			t.Fatal("a failed directory fsync must be reported, not discarded")
		}
		if !IsCommitted(err) {
			t.Fatalf("a post-rename sync failure must be a committed write, got %v", err)
		}
		got, readErr := os.ReadFile(dst)
		if readErr != nil {
			t.Fatalf("the copy is in place and must be kept: %v", readErr)
		}
		if string(got) != "material" {
			t.Fatalf("copied bytes = %q, want %q", got, "material")
		}
	})

	t.Run("pre-rename failures are not committed", func(t *testing.T) {
		dir := t.TempDir()
		// A source that cannot be read fails before anything is renamed.
		if err := CopyFile(filepath.Join(dir, "missing"), filepath.Join(dir, "dst")); err == nil {
			t.Fatal("copying a missing source must fail")
		} else if IsCommitted(err) {
			t.Fatalf("a pre-rename failure must not be reported as committed: %v", err)
		}
	})
}

// assertNoTempLeft fails if the atomic-write temp file survived.
func assertNoTempLeft(t *testing.T, dir, base string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != base {
			t.Fatalf("staged file %q left behind in %s", e.Name(), dir)
		}
	}
}
