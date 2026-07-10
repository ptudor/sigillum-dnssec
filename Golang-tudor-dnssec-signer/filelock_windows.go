//go:build windows

package main

import (
	"log/slog"
	"sync"
	"time"
)

// On Windows there is no flock. The signer's supported deployment is Unix (NSD/BIND), so
// cross-process locking is a documented no-op here; a process-local mutex still serializes
// concurrent goroutines within one process. Warned once so the limitation is visible.
type stateLock struct{}

var (
	winLockMu   sync.Mutex
	winLockWarn sync.Once
)

func acquireStateLock(_ string, _ time.Duration) (*stateLock, error) {
	winLockWarn.Do(func() {
		slog.Warn("[STATE] cross-process state locking is not implemented on Windows; concurrent daemon+CLI writes are not serialized")
	})
	winLockMu.Lock()
	return &stateLock{}, nil
}

func (l *stateLock) release() {
	winLockMu.Unlock()
}
