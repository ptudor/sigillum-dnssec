package fsutil

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// ownershipTarget captures the uid/gid of a reference directory (typically
// data_dir) so that files written under CLI commands running as root can be
// chowned to match the daemon user. Populated once at CLI startup by
// InitOwnershipTarget and read lock-free thereafter.
type ownershipTarget struct {
	uid    int
	gid    int
	active bool // true when we should actually chown (running as root + target is non-root)
	warned sync.Once
}

var ownership ownershipTarget

// Test seams: the effective uid and the chown syscall.
var (
	geteuid = os.Geteuid
	chownFn = os.Chown
)

// OwnershipStatus is the outcome of InitOwnershipTarget (RA6X-044).
type OwnershipStatus int

const (
	// OwnershipInactive: no ownership transfer applies (not root, or the
	// target is root-owned — a deliberate root-only deployment).
	OwnershipInactive OwnershipStatus = iota
	// OwnershipActive: running as root and the target is owned by another
	// account; every write is chowned to it as part of the write contract.
	OwnershipActive
	// OwnershipTargetMissing: running as root and the reference directory
	// does not exist, so there is no account to inherit. Mutating CLI
	// commands must not create a root-owned tree in that case; the operator
	// bootstraps the tree explicitly (see BootstrapInstructions).
	OwnershipTargetMissing
)

// InitOwnershipTarget inspects the given reference path (usually data_dir)
// and configures future writes to chown to that path's owner if the current
// process is running as root but the target is not root-owned. Called once
// at the start of any CLI command. Non-root invocations are a no-op, and
// invocations where data_dir is itself root-owned are a no-op.
//
// The result distinguishes "no target configured / not applicable"
// (OwnershipInactive), "target missing" (OwnershipTargetMissing) and a failed
// attempt to inspect the target, which is returned as an error rather than
// silently disabling ownership transfer (RA6X-044).
//
// A one-line warning is emitted on the first activation so the operator
// notices they ran a mutating command as root, while the chown itself
// ensures the daemon can still read what was written.
func InitOwnershipTarget(refPath string) (OwnershipStatus, error) {
	if geteuid() != 0 {
		return OwnershipInactive, nil // Non-root: whatever we write will be owned by the invoking user already.
	}

	info, err := os.Stat(refPath)
	if os.IsNotExist(err) {
		ownership.active = false
		return OwnershipTargetMissing, nil
	}
	if err != nil {
		ownership.active = false
		return OwnershipInactive, fmt.Errorf("inspecting ownership target %s: %w", refPath, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return OwnershipInactive, nil // Non-Unix platform; chown semantics don't apply.
	}
	if stat.Uid == 0 && stat.Gid == 0 {
		return OwnershipInactive, nil // Target is root-owned already; nothing to inherit.
	}

	ownership.uid = int(stat.Uid)
	ownership.gid = int(stat.Gid)
	ownership.active = true

	ownership.warned.Do(func() {
		slog.Warn("[CLI] running as root — writes will be chowned to match data_dir owner",
			"uid", ownership.uid, "gid", ownership.gid, "data_dir", refPath)
	})
	return OwnershipActive, nil
}

// BootstrapInstructions describes how to create the data directory tree
// before running a mutating command as root, so the tree is owned by the
// daemon account from the start instead of being created root-only and left
// unusable for an unprivileged daemon (RA6X-044). The account is never
// inferred; the operator names it.
func BootstrapInstructions(dataDir string) string {
	return fmt.Sprintf("data_dir %s does not exist and this command is running as root: creating it now would leave a root-owned tree the daemon account cannot read or write.\n"+
		"Create it first, owned by the daemon account (replace USER/GROUP):\n"+
		"    install -d -m 0750 -o USER -g GROUP %s\n"+
		"then re-run this command, or run it as the daemon account. For a deliberate root-only deployment, create the directory as root first.",
		dataDir, dataDir)
}

// ChownToTarget applies the captured uid/gid to path if ownership-matching
// is active and reports failure. Callers that stage a file must treat a
// failure as part of the write's failure (RA6X-044): a file the daemon
// account cannot read is not a successful write.
func ChownToTarget(path string) error {
	if !ownership.active {
		return nil
	}
	if err := chownFn(path, ownership.uid, ownership.gid); err != nil {
		return fmt.Errorf("chown %s to %d:%d: %w", path, ownership.uid, ownership.gid, err)
	}
	return nil
}

// WriteFileOwned writes data to path atomically with daemon ownership. It is
// WriteFileAtomicOwned under its historical name.
func WriteFileOwned(path string, data []byte, perm os.FileMode) error {
	return WriteFileAtomicOwned(path, data, perm)
}

// DurabilityError reports a commit that is VISIBLE (the rename succeeded) but
// whose directory entry could not be confirmed durable across a crash or
// power loss because the directory fsync failed (RA6X-049). Callers must
// treat the new file as the current generation — never delete or roll it
// back — and surface the uncertainty.
type DurabilityError struct {
	Path string
	Err  error
}

func (e *DurabilityError) Error() string {
	return fmt.Sprintf("%s was replaced but its directory entry could not be synced (durability across power loss uncertain): %v", e.Path, e.Err)
}

func (e *DurabilityError) Unwrap() error { return e.Err }

// IsCommitted reports whether err is a DurabilityError: the write is visible
// and only its durability is uncertain.
func IsCommitted(err error) bool {
	var d *DurabilityError
	return errors.As(err, &d)
}

// WriteFileAtomicOwned writes data to path atomically and durably: it writes to a unique
// temp file in the same directory, applies the mode, fsyncs, applies daemon ownership,
// renames over the destination, then fsyncs the directory. A crash leaves either the old
// file or the complete new one — never a truncated or half-written file (R-009). The
// unique temp name also avoids the fixed-".tmp" collision between a concurrent daemon and
// CLI writing the same path (R-002). On any error before the rename the temp file is
// removed and the predecessor is untouched — including a failed ownership assignment
// (RA6X-044). A directory-sync failure after the rename is returned as a
// *DurabilityError (RA6X-049).
func WriteFileAtomicOwned(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()

	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	// CreateTemp makes the file 0600; set the requested mode explicitly so it survives a
	// restrictive umask and matches what NSD / the daemon expect.
	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	// Ownership is assigned to the staged file BEFORE the rename; a rename
	// within the directory preserves it, so the replacement never appears
	// with the wrong owner.
	if err := ChownToTarget(tmpPath); err != nil {
		return fmt.Errorf("assigning daemon ownership to the staged replacement for %s (predecessor left in place): %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp file over %s: %w", path, err)
	}
	committed = true
	if err := SyncDir(dir); err != nil {
		return &DurabilityError{Path: path, Err: err}
	}
	return nil
}

// WriteConfigFileAtomic atomically and durably replaces the configuration file at
// path with data, preserving the DESTINATION file's existing owner (uid/gid) and
// mode — it never inherits data_dir/daemon ownership the way WriteFileAtomicOwned
// does (R-002). The config holds registrar API keys and hook commands and must stay
// owned as deployed (typically root, group-readable by the daemon, 0640); handing it
// to the daemon account would let a compromised daemon rewrite those commands/
// credentials. A failure to restore ownership aborts before replacing the original.
// A directory-sync failure after the rename is returned as a *DurabilityError.
func WriteConfigFileAtomic(path string, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat config file: %w", err)
	}
	perm := info.Mode().Perm()
	dir := filepath.Dir(path)

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp config in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing temp config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp config: %w", err)
	}
	// Preserve the destination's original owner on the temp file BEFORE the rename,
	// so the config never changes hands. Abort (leaving the original intact) if it fails.
	if err := preserveOwner(tmpPath, info); err != nil {
		return fmt.Errorf("preserving config ownership: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp config over %s: %w", path, err)
	}
	committed = true
	if err := SyncDir(dir); err != nil {
		return &DurabilityError{Path: path, Err: err}
	}
	return nil
}

// preserveOwner chowns path to the uid/gid recorded in info (a prior os.Stat of the
// replacement's destination). It is a no-op on non-Unix platforms and when not
// running as root (a non-root process cannot chown, and the file already carries the
// invoking user's ownership).
func preserveOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil // non-Unix: ownership model doesn't apply
	}
	if geteuid() != 0 {
		return nil
	}
	return chownFn(path, int(stat.Uid), int(stat.Gid))
}

// dirSyncUnsupported reports whether a directory fsync failure means the
// filesystem does not support syncing directory descriptors at all (some
// network and virtual filesystems answer EINVAL/ENOTSUP), as opposed to an
// I/O failure. Only the former is harmless (RA6X-049).
func dirSyncUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP)
}

var unsupportedDirSyncOnce sync.Once

// SyncDir fsyncs a directory so a preceding rename is durable across a crash/power loss.
// It returns the failure so callers can propagate the durability outcome (RA6X-049);
// a filesystem that does not support directory fsync at all is classified as such
// (logged once) and treated as success, while any other error is returned.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("opening directory %s for fsync: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		if dirSyncUnsupported(err) {
			unsupportedDirSyncOnce.Do(func() {
				slog.Warn("[FS] this filesystem does not support directory fsync; rename durability across power loss relies on the filesystem's own ordering",
					"dir", dir, "error", err)
			})
			return nil
		}
		return fmt.Errorf("fsync directory %s: %w", dir, err)
	}
	return nil
}

// CopyFile copies src to dst, preserving src's mode and applying daemon
// ownership to the destination so files written under a root CLI invocation
// (e.g. rollover key backups) stay readable by the daemon user. The copy is
// staged in a temp file and renamed into place, so an interrupted copy never
// leaves a truncated dst; the directory is then synced (a sync failure is
// returned as a *DurabilityError with dst already in place).
func CopyFile(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dst)+".*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(srcInfo.Mode().Perm()); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := io.Copy(tmp, in); err != nil {
		return fmt.Errorf("copying %s: %w", src, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := ChownToTarget(tmpPath); err != nil {
		return fmt.Errorf("assigning daemon ownership to the staged copy of %s: %w", src, err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("renaming temp file over %s: %w", dst, err)
	}
	committed = true
	if err := SyncDir(dir); err != nil {
		return &DurabilityError{Path: dst, Err: err}
	}
	return nil
}
