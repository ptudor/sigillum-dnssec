//go:build !windows

package main

import (
	"os/exec"
	"syscall"
	"time"
)

// configureHookProcess starts the hook in its own process group and makes
// cancellation terminate the whole group: the shell's descendants (the ones
// that inherit the stderr pipe and would otherwise outlive the timeout) get
// SIGTERM with the shell, and SIGKILL after hookKillGrace if any of them
// ignores it (RA6X-034).
func configureHookProcess(cmd *exec.Cmd) {
	grace := hookKillGrace // read once, on the caller's goroutine
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		pgid := cmd.Process.Pid
		if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
			return err
		}
		go func() {
			time.Sleep(grace)
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}()
		return nil
	}
}
