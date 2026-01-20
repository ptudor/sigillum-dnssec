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

// executeHook runs a post-sign hook command asynchronously with environment variables
func executeHook(cmd string, env *HookEnv) {
	if cmd == "" {
		return
	}

	go func() {
		startTime := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		slog.Debug("[HOOK] Executing post-sign hook", "command", cmd, "domain", env.Domain)

		command := exec.CommandContext(ctx, "sh", "-c", cmd)
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
				slog.Error("[HOOK] Post-sign hook timed out", "command", cmd, "domain", env.Domain)
			} else if stderr != "" {
				slog.Error("[HOOK] Post-sign hook failed", "command", cmd, "domain", env.Domain, "error", err, "stderr", stderr)
			} else {
				slog.Error("[HOOK] Post-sign hook failed", "command", cmd, "domain", env.Domain, "error", err)
			}
			return
		}

		duration := time.Since(startTime).Seconds()
		RecordHookExecution("post_sign", duration, true)
		slog.Debug("[HOOK] Post-sign hook completed successfully", "command", cmd, "domain", env.Domain, "duration_ms", int64(duration*1000))
	}()
}

// executeHookSync runs a hook synchronously and returns the error
func executeHookSync(cmd string) error {
	if cmd == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	slog.Debug("[HOOK] Executing hook synchronously", "command", cmd)

	command := exec.CommandContext(ctx, "sh", "-c", cmd)
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

	return out.Close()
}
