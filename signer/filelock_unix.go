//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/fsutil"
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
	// A root-owned 0600 lock file the daemon cannot open would silently skip
	// every daemon cycle; ownership assignment is part of taking the lock (RA6X-044).
	if err := fsutil.ChownToTarget(lockPath); err != nil {
		f.Close()
		return nil, err
	}

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
			return nil, fmt.Errorf("timed out after %s waiting for the state lock %s (another sigillum-signer process holds it)", timeout, lockPath)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// acquireInstanceLock takes the daemon-instance lock <dataDir>/serve.lock
// without waiting. A second `serve` against the same data_dir is refused here,
// before it has loaded or touched any shared state — port binding alone is not
// what authorizes a daemon to write (RA6X-006). CLI commands do not take this
// lock; they serialize against the daemon through the state lock as before.
func acquireInstanceLock(dataDir string) (*stateLock, error) {
	lockPath := filepath.Join(dataDir, "serve.lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening instance lock %s: %w", lockPath, err)
	}
	if err := fsutil.ChownToTarget(lockPath); err != nil {
		f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, fmt.Errorf("another sigillum-signer serve already holds %s; refusing to start a second instance against the same data_dir", lockPath)
		}
		return nil, fmt.Errorf("locking %s: %w", lockPath, err)
	}
	return &stateLock{f: f}, nil
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
