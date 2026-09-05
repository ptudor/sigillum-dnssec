package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ptudor/dnssec-tudor/internal/config"
	"github.com/ptudor/dnssec-tudor/internal/metrics"
)

// Hook execution (RA6X-034 lifecycle bounds, RA6X-043 shared CLI/daemon
// contract).
//
// A post-sign hook runs after zones were signed successfully. The daemon fires
// it asynchronously (tracked on a wait group so shutdown waits for it) and the
// CLI fires it synchronously (an async hook would be killed when the process
// exits). Both use the same invocation semantics (firePostSignHooks): with
// coalesce_post_sign the hook runs once per pass with DNSSEC_DOMAINS and
// DNSSEC_BATCH_SIZE for the zones that signed; otherwise once per signed zone
// with the per-zone variables. Inherited DNSSEC_* variables are always
// stripped so a script cannot read stale values from the parent environment,
// and a pass that signed nothing runs no hook.
//
// Every hook is bounded: the command gets hookTimeout, its process group is
// terminated (then killed) when that expires, and the wait for its stdout and
// stderr pipes is bounded by hookWaitDelay so a descendant that inherited the
// pipes cannot hold the caller past the timeout.

var (
	// hookTimeout bounds one hook invocation. Package variables (not
	// constants) so tests can shorten them.
	hookTimeout = 30 * time.Second
	// hookWaitDelay bounds how long Run waits for the hook's output pipes to
	// close after the process was cancelled or exited: a descendant holding
	// the inherited stderr pipe would otherwise block indefinitely.
	hookWaitDelay = 5 * time.Second
	// hookKillGrace is how long a timed-out process group gets to react to
	// SIGTERM before it is killed.
	hookKillGrace = 2 * time.Second
)

// maxHookStderr bounds how many bytes of a hook's stderr are retained. A broken
// hook that writes stderr continuously for up to the timeout could otherwise
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

// HookEnv contains environment variables passed to a per-zone hook.
type HookEnv struct {
	Domain     string // The domain that was signed
	ZonePath   string // Path to the unsigned zone file
	SignedPath string // Path to the signed zone file
	OutputDir  string // Output directory for signed zones
}

// SignedZoneRef identifies one zone a signing pass published: what the hook
// contract needs to describe it.
type SignedZoneRef struct {
	Domain     string
	ZonePath   string
	SignedPath string
}

// signedRef builds the hook reference for a zone from its source path and the
// configured output directory.
func signedRef(cfg *config.Config, domain, zonePath string) SignedZoneRef {
	return SignedZoneRef{
		Domain:     domain,
		ZonePath:   zonePath,
		SignedPath: filepath.Join(cfg.OutputDir, domain+".zone.signed"),
	}
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

// hookConfigured reports whether a post-sign hook is set.
func hookConfigured(hooks *config.HooksConfig) bool {
	_, _, _, ok := hookCmd(hooks)
	return ok
}

// hookEnviron builds a hook's environment: the parent environment with every
// inherited DNSSEC_* variable removed, plus exactly the variables of the
// invocation mode, so a script never reads a stale or opposite-mode value.
func hookEnviron(vars ...string) []string {
	env := make([]string, 0, len(os.Environ())+len(vars))
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "DNSSEC_") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, vars...)
}

func perZoneVars(env *HookEnv) []string {
	return []string{
		fmt.Sprintf("DNSSEC_DOMAIN=%s", env.Domain),
		fmt.Sprintf("DNSSEC_ZONE_PATH=%s", env.ZonePath),
		fmt.Sprintf("DNSSEC_SIGNED_PATH=%s", env.SignedPath),
		fmt.Sprintf("DNSSEC_OUTPUT_DIR=%s", env.OutputDir),
	}
}

func batchVars(domains []string, outputDir string) []string {
	return []string{
		fmt.Sprintf("DNSSEC_DOMAINS=%s", strings.Join(domains, " ")),
		fmt.Sprintf("DNSSEC_BATCH_SIZE=%d", len(domains)),
		fmt.Sprintf("DNSSEC_OUTPUT_DIR=%s", outputDir),
	}
}

// errHookTimeout marks a hook that exceeded hookTimeout.
var errHookTimeout = errors.New("hook timed out")

// runHook runs one hook invocation to completion with bounded lifetime: the
// command is started in its own process group, cancelled as a group when
// hookTimeout expires (terminate, then kill after hookKillGrace), and the
// output pipes are waited on for at most hookWaitDelay after that. stderr is
// captured as a bounded prefix and returned with the error.
func runHook(hooks *config.HooksConfig, env []string, stdout io.Writer) (stderr string, err error) {
	name, args, _, ok := hookCmd(hooks)
	if !ok {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()

	command := exec.CommandContext(ctx, name, args...)
	command.Stdout = stdout
	// Capture a BOUNDED prefix of stderr for error reporting: a broken hook that
	// writes continuously must not allocate until the daemon is killed (R-023).
	stderrBuf := &cappedBuffer{max: maxHookStderr}
	command.Stderr = stderrBuf
	command.Env = env
	command.WaitDelay = hookWaitDelay
	configureHookProcess(command)

	runErr := command.Run()
	stderr = strings.TrimSpace(stderrBuf.String())
	if runErr == nil {
		return stderr, nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		return stderr, fmt.Errorf("%w after %s: %v", errHookTimeout, hookTimeout, runErr)
	}
	return stderr, runErr
}

// logHookResult records the outcome of one hook invocation.
func logHookResult(kind, identity string, attrs []any, stderr string, err error, start time.Time) {
	duration := time.Since(start).Seconds()
	metrics.RecordHookExecution(kind, duration, err == nil)
	fields := append([]any{"hook", identity}, attrs...)
	switch {
	case err == nil:
		slog.Debug("[HOOK] Hook completed", append(fields, "duration_ms", int64(duration*1000))...)
	case errors.Is(err, errHookTimeout):
		slog.Error("[HOOK] Hook timed out; its process group was terminated", append(fields, "error", err)...)
	case stderr != "":
		slog.Error("[HOOK] Hook failed", append(fields, "error", err, "stderr", stderr)...)
	default:
		slog.Error("[HOOK] Hook failed", append(fields, "error", err)...)
	}
}

// firePostSignHooks applies the post-sign hook contract to the zones a pass
// signed successfully (RA6X-043). With coalescing, one batch invocation
// receives every domain (even a single one); otherwise each zone gets its own
// invocation with its exact source and output paths. When wg is non-nil the
// invocations run asynchronously and are tracked on it (the daemon); when it
// is nil they run synchronously and the first failure is returned (the CLI).
// A pass that signed nothing runs no hook.
func firePostSignHooks(hooks *config.HooksConfig, outputDir string, signed []SignedZoneRef, wg *sync.WaitGroup) error {
	if !hookConfigured(hooks) || len(signed) == 0 {
		return nil
	}
	_, _, identity, _ := hookCmd(hooks)

	type invocation struct {
		kind  string
		env   []string
		attrs []any
	}
	var invocations []invocation
	if hooks.CoalescePostSign {
		domains := make([]string, len(signed))
		for i, z := range signed {
			domains[i] = z.Domain
		}
		invocations = append(invocations, invocation{
			kind:  "post_sign_batch",
			env:   hookEnviron(batchVars(domains, outputDir)...),
			attrs: []any{"batch_size", len(domains)},
		})
	} else {
		for _, z := range signed {
			invocations = append(invocations, invocation{
				kind:  "post_sign",
				env:   hookEnviron(perZoneVars(&HookEnv{Domain: z.Domain, ZonePath: z.ZonePath, SignedPath: z.SignedPath, OutputDir: outputDir})...),
				attrs: []any{"domain", z.Domain},
			})
		}
	}

	run := func(inv invocation, stdout io.Writer) error {
		start := time.Now()
		slog.Debug("[HOOK] Executing hook", append([]any{"hook", identity}, inv.attrs...)...)
		stderr, err := runHook(hooks, inv.env, stdout)
		logHookResult(inv.kind, identity, inv.attrs, stderr, err, start)
		return err
	}

	if wg == nil {
		var first error
		for _, inv := range invocations {
			if err := run(inv, os.Stdout); err != nil && first == nil {
				first = err
			}
		}
		return first
	}
	for _, inv := range invocations {
		inv := inv
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					slog.Error("[HOOK] Panic in post-sign hook", append([]any{"panic", r, "hook", identity}, inv.attrs...)...)
				}
			}()
			_ = run(inv, io.Discard)
		}()
	}
	return nil
}

// executeHookSync runs a per-zone hook synchronously with env's variables and
// returns its error. It bypasses the coalescing contract (callers that want
// the contract use firePostSignHooks) and exists for direct invocation.
func executeHookSync(hooks *config.HooksConfig, env *HookEnv) error {
	if !hookConfigured(hooks) {
		return nil
	}
	_, _, identity, _ := hookCmd(hooks)
	var vars []string
	if env != nil {
		vars = perZoneVars(env)
	}
	start := time.Now()
	stderr, err := runHook(hooks, hookEnviron(vars...), os.Stdout)
	if stderr != "" {
		fmt.Fprintln(os.Stderr, stderr)
	}
	logHookResult("post_sign", identity, nil, stderr, err, start)
	return err
}
