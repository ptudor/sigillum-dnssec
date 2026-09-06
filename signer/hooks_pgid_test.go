//go:build !windows

package main

import (
	"context"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The delayed SIGKILL that escalates a timed-out hook (RA6X-034) targets a
// process-GROUP id. Once the hook has been reaped that id is free for the
// kernel to reassign, so a SIGKILL fired after the fact could kill an
// unrelated process group. configureHookProcess returns a release function
// that cancels the pending signal; runHook defers it.
//
// The child ignores SIGTERM and keeps its own shell alive across it, so the
// group survives the cancellation signal and is still there when the grace
// period ends. With the release honoured it is still running afterwards; with
// an unconditional delayed SIGKILL it is not.
func TestConfigureHookProcess_ReleaseCancelsTheDelayedKill(t *testing.T) {
	origGrace := hookKillGrace
	hookKillGrace = 400 * time.Millisecond
	t.Cleanup(func() { hookKillGrace = origGrace })

	// cmd.Cancel is only honoured on a CommandContext, and it is the context
	// becoming done that invokes it — the same path a hook timeout takes.
	ctx, cancelCtx := context.WithCancel(context.Background())
	// The shell ignores SIGTERM and re-runs a short sleep, so killing the
	// group's other members does not end the group; only SIGKILL does.
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "trap '' TERM; while :; do sleep 0.05; done")
	release := configureHookProcess(cmd)
	if err := cmd.Start(); err != nil {
		cancelCtx()
		t.Fatalf("starting the child: %v", err)
	}
	pgid := cmd.Process.Pid
	t.Cleanup(func() {
		cancelCtx()
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		_ = cmd.Wait()
	})

	// Let the shell install its SIGTERM trap before cancelling; a signal that
	// arrives first takes the default action and ends the group for reasons
	// that have nothing to do with the delayed kill.
	time.Sleep(200 * time.Millisecond)

	// Simulate the timeout (SIGTERM to the group, delayed SIGKILL armed),
	// then the reap that release() stands for.
	cancelCtx()
	time.Sleep(100 * time.Millisecond) // let exec's watchdog run cmd.Cancel
	if err := syscall.Kill(-pgid, 0); err != nil {
		t.Skipf("the child's process group did not survive SIGTERM (%v); this platform cannot host the check", err)
	}
	release()

	time.Sleep(3 * hookKillGrace)

	// Signal 0 probes for existence without delivering anything.
	if err := syscall.Kill(-pgid, 0); err != nil {
		t.Fatalf("the process group was killed after release cancelled the pending SIGKILL (%v); "+
			"a delayed kill must never outlive the reaped hook, or it can hit a recycled process-group id", err)
	}
}

// release must be safe to call more than once: runHook defers it on every
// path, including ones where the hook was never cancelled.
func TestConfigureHookProcess_ReleaseIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", "exit 0")
	release := configureHookProcess(cmd)
	release()
	release()
}
