package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// HookEnv contains environment variables passed to hooks
type HookEnv struct {
	Domain     string // The domain that was signed
	ZonePath   string // Path to the unsigned zone file
	SignedPath string // Path to the signed zone file
	OutputDir  string // Output directory for signed zones
}

// hookCmd returns the command name and arguments for a hook, along with a
// log-safe identity string. When PostSignCmd is set, it is used directly as
// exec-style. When PostSign is set and Shell is true, it is wrapped in sh -c.
// When PostSign is set and Shell is false, it is split on whitespace.
func hookCmd(hooks *HooksConfig) (name string, args []string, identity string, ok bool) {
	if len(hooks.PostSignCmd) > 0 {
		return hooks.PostSignCmd[0], hooks.PostSignCmd[1:], "post_sign", true
	}
	if hooks.PostSign == "" {
		return "", nil, "", false
	}
	if hooks.Shell {
		return "sh", []string{"-c", hooks.PostSign}, "post_sign(shell)", true
	}
	// Split on whitespace for simple exec-style
	parts := strings.Fields(hooks.PostSign)
	if len(parts) == 0 {
		return "", nil, "", false
	}
	return parts[0], parts[1:], "post_sign", true
}

// executeHook runs a post-sign hook command asynchronously with environment variables.
// Log messages contain the hook identity (e.g., "post_sign") and outcome only—
// raw command strings are never logged.
func executeHook(hooks *HooksConfig, env *HookEnv) {
	name, args, identity, ok := hookCmd(hooks)
	if !ok {
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("[HOOK] Panic in post-sign hook", "panic", r, "hook", identity, "domain", env.Domain)
			}
		}()

		startTime := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		slog.Debug("[HOOK] Executing hook", "hook", identity, "domain", env.Domain)

		command := exec.CommandContext(ctx, name, args...)
		command.Stdout = io.Discard

		// Capture stderr for error reporting
		var stderrBuf bytes.Buffer
		command.Stderr = &stderrBuf

		// Set environment variables for the hook
		command.Env = append(os.Environ(),
			fmt.Sprintf("DNSSEC_DOMAIN=%s", env.Domain),
			fmt.Sprintf("DNSSEC_ZONE_PATH=%s", env.ZonePath),
			fmt.Sprintf("DNSSEC_SIGNED_PATH=%s", env.SignedPath),
			fmt.Sprintf("DNSSEC_OUTPUT_DIR=%s", env.OutputDir),
		)

		if err := command.Run(); err != nil {
			duration := time.Since(startTime).Seconds()
			RecordHookExecution("post_sign", duration, false)
			stderr := strings.TrimSpace(stderrBuf.String())
			if ctx.Err() == context.DeadlineExceeded {
				slog.Error("[HOOK] Hook timed out", "hook", identity, "domain", env.Domain)
			} else if stderr != "" {
				slog.Error("[HOOK] Hook failed", "hook", identity, "domain", env.Domain, "error", err, "stderr", stderr)
			} else {
				slog.Error("[HOOK] Hook failed", "hook", identity, "domain", env.Domain, "error", err)
			}
			return
		}

		duration := time.Since(startTime).Seconds()
		RecordHookExecution("post_sign", duration, true)
		slog.Debug("[HOOK] Hook completed successfully", "hook", identity, "domain", env.Domain, "duration_ms", int64(duration*1000))
	}()
}

// executeHookSync runs a hook synchronously and returns the error.
// Used for CLI commands where we want to wait for completion.
func executeHookSync(hooks *HooksConfig) error {
	name, args, identity, ok := hookCmd(hooks)
	if !ok {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	slog.Debug("[HOOK] Executing hook synchronously", "hook", identity)

	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr

	return command.Run()
}

// copyFile copies a file from src to dst, preserving permissions
func copyFile(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	if err := out.Close(); err != nil {
		return err
	}
	// Mirror the ownership helper so rollover backups written under a
	// root CLI invocation stay readable by the daemon user.
	chownToTarget(dst)
	return nil
}
