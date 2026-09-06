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
//
// It returns a release function the caller MUST defer. The delayed SIGKILL
// targets a process-group id, and once the hook has been reaped that id is
// free for the kernel to reassign; signalling it then would kill an unrelated
// process group. release cancels the pending SIGKILL, so the signal is only
// ever sent while the group is known to still be ours.
func configureHookProcess(cmd *exec.Cmd) (release func()) {
	grace := hookKillGrace // read once, on the caller's goroutine
	reaped := make(chan struct{})
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		pgid := cmd.Process.Pid
		if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
			return err
		}
		go func() {
			timer := time.NewTimer(grace)
			defer timer.Stop()
			select {
			case <-timer.C:
				_ = syscall.Kill(-pgid, syscall.SIGKILL)
			case <-reaped:
				// The hook and its group are gone; the pgid may already have
				// been reassigned, so send nothing.
			}
		}()
		return nil
	}
	var once bool
	return func() {
		if !once {
			once = true
			close(reaped)
		}
	}
}
