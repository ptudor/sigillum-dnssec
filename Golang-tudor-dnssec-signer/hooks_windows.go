//go:build windows

package main

import "os/exec"

// configureHookProcess leaves the default cancellation (kill the direct
// process) in place; process-group termination is a Unix facility.
func configureHookProcess(cmd *exec.Cmd) {}
