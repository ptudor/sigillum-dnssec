package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"time"
)

// executeHook runs a post-sign hook command asynchronously
func executeHook(cmd string) {
	if cmd == "" {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		slog.Debug("Executing post-sign hook", "command", cmd)

		command := exec.CommandContext(ctx, "sh", "-c", cmd)
		command.Stdout = io.Discard
		command.Stderr = io.Discard

		if err := command.Run(); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				slog.Error("Post-sign hook timed out", "command", cmd)
			} else {
				slog.Error("Post-sign hook failed", "command", cmd, "error", err)
			}
			return
		}

		slog.Debug("Post-sign hook completed successfully", "command", cmd)
	}()
}

// executeHookSync runs a hook synchronously and returns the error
func executeHookSync(cmd string) error {
	if cmd == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	slog.Debug("Executing hook synchronously", "command", cmd)

	command := exec.CommandContext(ctx, "sh", "-c", cmd)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr

	return command.Run()
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Close()
}
