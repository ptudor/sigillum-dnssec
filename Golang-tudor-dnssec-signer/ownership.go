package main

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"syscall"
)

// ownershipTarget captures the uid/gid of a reference directory (typically
// data_dir) so that files written under CLI commands running as root can be
// chowned to match the daemon user. Populated once at CLI startup by
// InitOwnershipTarget and read lock-free thereafter.
type ownershipTarget struct {
	uid     int
	gid     int
	active  bool // true when we should actually chown (running as root + target is non-root)
	warned  sync.Once
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
		// data_dir might not exist yet (first add); fall back to its parent.
		// If that fails too, we quietly skip chowning — better than blocking.
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

// chownToTarget applies the captured uid/gid to path if ownership-matching
// is active. Silent no-op otherwise. Chown errors are logged but not
// returned — the write already succeeded, and a chown failure at worst
// recreates the original permission-denied problem on the daemon side
// (which the operator will see in logs just as before).
func chownToTarget(path string) {
	if !ownership.active {
		return
	}
	if err := os.Chown(path, ownership.uid, ownership.gid); err != nil {
		slog.Warn("[CLI] chown failed after write",
			"path", path, "uid", ownership.uid, "gid", ownership.gid, "error", err)
	}
}

// writeFileOwned wraps os.WriteFile with the chown step. Used for both
// state.json and key files. Returns the os.WriteFile error verbatim so
// callers' error wrapping stays consistent.
func writeFileOwned(path string, data []byte, perm os.FileMode) error {
	if err := os.WriteFile(path, data, perm); err != nil {
		return err
	}
	chownToTarget(path)
	return nil
}

// renameOwned wraps os.Rename with a post-rename chown. The source temp
// file may already have the right owner from writeFileOwned, but rename
// across the same directory preserves ownership only on Unix — an explicit
// chown on the destination is a safety belt for the case where the source
// was created without the helper (e.g. a future code path that forgets).
func renameOwned(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	chownToTarget(dst)
	return nil
}

// cliRootAdvisory returns a human-readable description of what the CLI is
// about to do regarding ownership. Used by commands that want to surface
// it in their own output (e.g. `add`) in addition to the startup warning.
// Empty string when no adjustment will happen.
func cliRootAdvisory() string {
	if !ownership.active {
		return ""
	}
	return fmt.Sprintf("running as root; files will be chowned to uid=%d gid=%d", ownership.uid, ownership.gid)
}
