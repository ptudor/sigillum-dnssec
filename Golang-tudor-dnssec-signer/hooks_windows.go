//go:build windows

package main

import "os/exec"

// configureHookProcess leaves the default cancellation (kill the direct
// process) in place; process-group termination is a Unix facility. The
// returned release function exists so callers are identical on both
// platforms and does nothing here.
func configureHookProcess(cmd *exec.Cmd) (release func()) { return func() {} }
