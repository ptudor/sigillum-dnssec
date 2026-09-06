//go:build !windows

package signer

import (
	"os"
	"syscall"
)

// openSourceFile opens an unsigned zone file for a snapshot read without
// blocking: opening a FIFO for reading would otherwise wait for a writer
// while the signer holds the state lock. Regular files are unaffected; the
// caller rejects anything else after inspecting the descriptor.
func openSourceFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
