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
	"sync"
	"time"

	"github.com/ptudor/dnssec-tudor/internal/config"
	"github.com/ptudor/dnssec-tudor/internal/fsutil"
)

// maxHookStderr bounds how many bytes of a hook's stderr are retained. A broken
// hook that writes stderr continuously for up to the 30s timeout could otherwise
// allocate an unbounded bytes.Buffer and OOM the daemon (R-023). 64 KiB is ample
// for a diagnostic prefix.
const maxHookStderr = 64 * 1024

// cappedBuffer is an io.Writer that retains at most max bytes of what is written
// (a prefix), discarding the rest, and always reports the full write length so the
// child's stderr pipe keeps draining and cannot deadlock the hook (R-023).
type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := c.max - c.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			c.buf.Write(p[:remaining])
			c.truncated = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil // always drain fully
}

// String returns the captured stderr prefix, with an explicit marker when the
// output was truncated.
func (c *cappedBuffer) String() string {
	s := c.buf.String()
	if c.truncated {
		s += "\n[stderr truncated]"
	}
	return s
}

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
func hookCmd(hooks *config.HooksConfig) (name string, args []string, identity string, ok bool) {
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
// raw command strings are never logged. When wg is non-nil (the daemon path) the
// goroutine is tracked on it so shutdown can wait for the hook to finish before
// the process exits (R-026); CLI callers pass nil.
func executeHook(hooks *config.HooksConfig, env *HookEnv, wg *sync.WaitGroup) {
	name, args, identity, ok := hookCmd(hooks)
	if !ok {
		return
	}

	if wg != nil {
		wg.Add(1)
	}
	go func() {
		if wg != nil {
			defer wg.Done()
		}
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

		// Capture a BOUNDED prefix of stderr for error reporting: a broken hook that
		// writes continuously must not allocate until the daemon is killed (R-023).
		stderrBuf := &cappedBuffer{max: maxHookStderr}
		command.Stderr = stderrBuf

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

// executeBatchHook runs a post-sign hook once for a batch of signed
// domains. Used by the daemon when coalesce_post_sign is enabled so a
// single cycle that signs N zones produces one hook invocation rather
// than N. The hook receives `DNSSEC_DOMAINS` (space-separated) instead
// of the per-zone `DNSSEC_DOMAIN` — consumers like `nsd-control reload`
// don't need per-zone paths, and a full reload is cheaper than N
// targeted reloads at scale. A zero-length domains slice is a no-op.
func executeBatchHook(hooks *config.HooksConfig, domains []string, outputDir string, wg *sync.WaitGroup) {
	name, args, identity, ok := hookCmd(hooks)
	if !ok || len(domains) == 0 {
		return
	}

	if wg != nil {
		wg.Add(1)
	}
	go func() {
		if wg != nil {
			defer wg.Done()
		}
		defer func() {
			if r := recover(); r != nil {
				slog.Error("[HOOK] Panic in post-sign hook", "panic", r, "hook", identity, "batch_size", len(domains))
			}
		}()

		startTime := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		slog.Debug("[HOOK] Executing batched hook", "hook", identity, "batch_size", len(domains))

		command := exec.CommandContext(ctx, name, args...)
		command.Stdout = io.Discard
		// Bounded stderr capture (R-023): a runaway batch hook must not exhaust memory.
		stderrBuf := &cappedBuffer{max: maxHookStderr}
		command.Stderr = stderrBuf

		// DNSSEC_DOMAINS is the batched counterpart of DNSSEC_DOMAIN.
		// Consumers that used $DNSSEC_DOMAIN in per-zone hooks need to
		// switch to iterating $DNSSEC_DOMAINS, or just issue a reload-all.
		command.Env = append(os.Environ(),
			fmt.Sprintf("DNSSEC_DOMAINS=%s", strings.Join(domains, " ")),
			fmt.Sprintf("DNSSEC_BATCH_SIZE=%d", len(domains)),
			fmt.Sprintf("DNSSEC_OUTPUT_DIR=%s", outputDir),
		)

		if err := command.Run(); err != nil {
			duration := time.Since(startTime).Seconds()
			RecordHookExecution("post_sign_batch", duration, false)
			stderr := strings.TrimSpace(stderrBuf.String())
			if ctx.Err() == context.DeadlineExceeded {
				slog.Error("[HOOK] Batched hook timed out", "hook", identity, "batch_size", len(domains))
			} else if stderr != "" {
				slog.Error("[HOOK] Batched hook failed", "hook", identity, "batch_size", len(domains), "error", err, "stderr", stderr)
			} else {
				slog.Error("[HOOK] Batched hook failed", "hook", identity, "batch_size", len(domains), "error", err)
			}
			return
		}

		duration := time.Since(startTime).Seconds()
		RecordHookExecution("post_sign_batch", duration, true)
		slog.Debug("[HOOK] Batched hook completed", "hook", identity, "batch_size", len(domains), "duration_ms", int64(duration*1000))
	}()
}

// executeHookSync runs a hook synchronously and returns the error.
// Used for CLI commands, which must wait for completion — an async hook
// spawned from a CLI command would be killed when the process exits.
// env may be nil; when set, the same DNSSEC_* variables the daemon's
// per-zone hook receives are exported.
func executeHookSync(hooks *config.HooksConfig, env *HookEnv) error {
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
	if env != nil {
		command.Env = append(os.Environ(),
			fmt.Sprintf("DNSSEC_DOMAIN=%s", env.Domain),
			fmt.Sprintf("DNSSEC_ZONE_PATH=%s", env.ZonePath),
			fmt.Sprintf("DNSSEC_SIGNED_PATH=%s", env.SignedPath),
			fmt.Sprintf("DNSSEC_OUTPUT_DIR=%s", env.OutputDir),
		)
	}

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
	fsutil.ChownToTarget(dst)
	return nil
}
