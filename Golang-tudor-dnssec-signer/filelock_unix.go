//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// stateLock is an advisory cross-process lock over state.json, held via flock on a sidecar
// lock file in data_dir. It serializes the daemon's whole signing cycle against mutating
// CLI commands (and CLI commands against each other) so a CLI write can't be clobbered by
// the daemon's end-of-cycle Save, and a rollover started mid-cycle can't be reverted
// (R-007). Read-only commands do not take it.
type stateLock struct {
	f *os.File
}

// acquireStateLock opens (creating if needed) <dataDir>/state.json.lock and blocks up to
// timeout for an exclusive advisory lock.
func acquireStateLock(dataDir string, timeout time.Duration) (*stateLock, error) {
	lockPath := filepath.Join(dataDir, "state.json.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening lock file %s: %w", lockPath, err)
	}
	chownToTarget(lockPath)

	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return &stateLock{f: f}, nil
		}
		if err != syscall.EWOULDBLOCK {
			f.Close()
			return nil, fmt.Errorf("locking %s: %w", lockPath, err)
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, fmt.Errorf("timed out after %s waiting for the state lock %s (another dnssec-tudor process holds it)", timeout, lockPath)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// release unlocks and closes the lock file. Safe to call multiple times / on nil.
func (l *stateLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}
