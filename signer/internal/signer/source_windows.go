//go:build windows

package signer

import "os"

// openSourceFile opens an unsigned zone file for a snapshot read; the caller
// rejects anything that is not a regular file.
func openSourceFile(path string) (*os.File, error) {
	return os.Open(path)
}
