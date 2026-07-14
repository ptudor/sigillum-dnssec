package fsutil

import (
	"fmt"
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

// InitOwnershipTarget inspects the given reference path (usually data_dir)
// and configures future writes to chown to that path's owner if the current
// process is running as root but the target is not root-owned. Called once
// at the start of any mutating CLI command. Non-root invocations are a
// no-op, and invocations where data_dir is itself root-owned are a no-op.
//
// A one-line warning is emitted on the first activation so the operator
// notices they ran a mutating command as root, while the chown itself
// ensures the daemon can still read what was written.
func InitOwnershipTarget(refPath string) {
	if os.Geteuid() != 0 {
		return // Non-root: whatever we write will be owned by the invoking user already.
	}

	info, err := os.Stat(refPath)
	if err != nil {
		// data_dir may not exist yet (e.g. first `add`). We can't infer an
		// owner to inherit, so we quietly skip chowning rather than block the
		// command — the daemon runs as its own user and will create/own the
		// tree itself on first start.
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return // Non-Unix platform; chown semantics don't apply.
	}
	if stat.Uid == 0 && stat.Gid == 0 {
		return // Target is root-owned already; nothing to inherit.
	}

	ownership.uid = int(stat.Uid)
	ownership.gid = int(stat.Gid)
	ownership.active = true

	ownership.warned.Do(func() {
		slog.Warn("[CLI] running as root — writes will be chowned to match data_dir owner",
			"uid", ownership.uid, "gid", ownership.gid, "data_dir", refPath)
	})
}

// ChownToTarget applies the captured uid/gid to path if ownership-matching
// is active. Silent no-op otherwise. Chown errors are logged but not
// returned — the write already succeeded, and a chown failure at worst
// recreates the original permission-denied problem on the daemon side
// (which the operator will see in logs just as before).
func ChownToTarget(path string) {
	if !ownership.active {
		return
	}
	if err := os.Chown(path, ownership.uid, ownership.gid); err != nil {
		slog.Warn("[CLI] chown failed after write",
			"path", path, "uid", ownership.uid, "gid", ownership.gid, "error", err)
	}
}

// WriteFileOwned wraps os.WriteFile with the chown step. Used for both
// state.json and key files. Returns the os.WriteFile error verbatim so
// callers' error wrapping stays consistent.
func WriteFileOwned(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	ChownToTarget(path)
	return nil
}

// renameOwned wraps os.Rename with a post-rename chown. The source temp
// file may already have the right owner from WriteFileOwned, but rename
// across the same directory preserves ownership only on Unix — an explicit
// chown on the destination is a safety belt for the case where the source
// was created without the helper (e.g. a future code path that forgets).
func renameOwned(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	ChownToTarget(dst)
	return nil
}

// WriteFileAtomicOwned writes data to path atomically and durably: it writes to a unique
// temp file in the same directory, applies the mode, fsyncs, applies daemon ownership,
// renames over the destination, then fsyncs the directory. A crash leaves either the old
// file or the complete new one — never a truncated or half-written file (R-009). The
// unique temp name also avoids the fixed-".tmp" collision between a concurrent daemon and
// CLI writing the same path (R-002). On any error the temp file is removed.
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
	ChownToTarget(tmpPath)
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming temp file over %s: %w", path, err)
	}
	committed = true
	ChownToTarget(path)
	SyncDir(dir)
	return nil
}

// WriteConfigFileAtomic atomically and durably replaces the configuration file at
// path with data, preserving the DESTINATION file's existing owner (uid/gid) and
// mode — it never inherits data_dir/daemon ownership the way WriteFileAtomicOwned
// does (R-002). The config holds registrar API keys and hook commands and must stay
// owned as deployed (typically root, group-readable by the daemon, 0640); handing it
// to the daemon account would let a compromised daemon rewrite those commands/
// credentials. A failure to restore ownership aborts before replacing the original.
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
	SyncDir(dir)
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
	if os.Geteuid() != 0 {
		return nil
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}

// SyncDir fsyncs a directory so a preceding rename is durable across a crash/power loss.
// Best-effort: a failure is logged, not returned (the rename already succeeded).
func SyncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		slog.Debug("[FS] Cannot open directory for fsync", "dir", dir, "error", err)
		return
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		slog.Debug("[FS] Directory fsync failed", "dir", dir, "error", err)
	}
}
