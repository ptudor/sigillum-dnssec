//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-018: asynchronous hooks go through a bounded, single-flight
// dispatcher. One publication generation has at most one queued/running
// invocation, the number of simultaneous hook processes never exceeds the
// bound, a failed generation is retried only after completion and a bounded
// backoff (unless the hook command changed), a newer generation supersedes a
// still-queued older one, and shutdown stays bounded with work queued.

// hookTrace is a hook that logs "start <domain> <ns>" and "end <domain> <ns>"
// and, when block is set, waits for a release file between the two.
type hookTrace struct {
	log     string
	release string
}

func newHookTrace(t *testing.T, block bool) *hookTrace {
	t.Helper()
	dir := t.TempDir()
	h := &hookTrace{log: filepath.Join(dir, "trace.log")}
	if block {
		h.release = filepath.Join(dir, "release")
	}
	return h
}

func (h *hookTrace) cmd(exit int, hold time.Duration) []string {
	script := "d=\"${DNSSEC_DOMAIN:-$DNSSEC_DOMAINS}\"; echo \"start $d $(date +%s%N)\" >> " + h.log + "; "
	if h.release != "" {
		script += "while [ ! -f " + h.release + " ]; do sleep 0.02; done; "
	}
	if hold > 0 {
		script += fmt.Sprintf("sleep %.2f; ", hold.Seconds())
	}
	script += "echo \"end $d $(date +%s%N)\" >> " + h.log + "; exit " + strconv.Itoa(exit)
	return []string{"/bin/sh", "-c", script}
}

func (h *hookTrace) releaseAll(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(h.release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

type traceEvent struct {
	kind, domain string
	at           int64
}

func (h *hookTrace) events(t *testing.T) []traceEvent {
	t.Helper()
	data, err := os.ReadFile(h.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []traceEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		at, _ := strconv.ParseInt(f[len(f)-1], 10, 64)
		out = append(out, traceEvent{kind: f[0], domain: strings.Join(f[1:len(f)-1], " "), at: at})
	}
	return out
}

func (h *hookTrace) starts(t *testing.T, domain string) int {
	t.Helper()
	n := 0
	for _, e := range h.events(t) {
		if e.kind == "start" && (domain == "" || e.domain == domain) {
			n++
		}
	}
	return n
}

// maxOverlap computes the maximum number of hook processes alive at once.
func (h *hookTrace) maxOverlap(t *testing.T) int {
	t.Helper()
	ev := h.events(t)
	sort.Slice(ev, func(i, j int) bool {
		if ev[i].at != ev[j].at {
			return ev[i].at < ev[j].at
		}
		return ev[i].kind == "end" // an end at the same instant precedes a start
	})
	cur, max := 0, 0
	for _, e := range ev {
		if e.kind == "start" {
			cur++
			if cur > max {
				max = cur
			}
		} else {
			cur--
		}
	}
	return max
}

// waitStarts waits until the trace shows n hook starts (the hook process is
// started asynchronously by a dispatcher worker).
func (h *hookTrace) waitStarts(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.starts(t, "") >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d hook start(s) within 5s, got %d", n, h.starts(t, ""))
}

func setHookConcurrency(t *testing.T, n int) {
	t.Helper()
	orig := hookMaxConcurrent
	hookMaxConcurrent = n
	t.Cleanup(func() { hookMaxConcurrent = orig })
}

// multiZoneDaemon builds a daemon managing n signable zones.
func multiZoneDaemon(t *testing.T, n int) (*Daemon, *config.Config, *statepkg.State, []string) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	cfg.LoadedAt = time.Now().UTC()
	for _, dir := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := signerpkg.EnsureDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	state := statepkg.NewState(cfg.StatePath())
	kg := signerpkg.NewKeyGenerator(cfg)
	var domains []string
	for i := 0; i < n; i++ {
		domain := fmt.Sprintf("z%02d.example.", i)
		zonePath := filepath.Join(dataDir, domain+"zone")
		if err := os.WriteFile(zonePath, []byte(validZoneContent(strings.TrimSuffix(domain, "."))), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}
		ksk, err := kg.GenerateKSK(domain)
		if err != nil {
			t.Fatal(err)
		}
		zsk, err := kg.GenerateZSK(domain)
		if err != nil {
			t.Fatal(err)
		}
		state.SetZone(domain, &statepkg.ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return NewDaemon(cfg, state), cfg, state, domains
}

// One generation has at most one queued/running invocation across many short
// poll cycles, in both per-zone and coalesced modes.
func TestRDAYBLUEX018_SingleFlightPerGeneration(t *testing.T) {
	for _, coalesce := range []bool{false, true} {
		t.Run(fmt.Sprintf("coalesce=%v", coalesce), func(t *testing.T) {
			d, cfg, state, domain := signableZoneDaemon(t)
			cfg.LoadedAt = time.Now().UTC()
			tr := newHookTrace(t, true)
			cfg.Hooks.PostSignCmd = tr.cmd(0, 0)
			cfg.Hooks.CoalescePostSign = coalesce

			d.signAllZones() // generation 1 signed; its hook starts and blocks
			tr.waitStarts(t, 1)
			for i := 0; i < 6; i++ {
				d.signAllZones() // pending retry attempts must NOT start another
				time.Sleep(50 * time.Millisecond)
			}
			if n := tr.starts(t, ""); n != 1 {
				t.Fatalf("a generation that is still running must not be started again; got %d starts", n)
			}
			if q := d.hooks.queued(); q != 0 {
				t.Fatalf("nothing may be queued for a running generation, got %d", q)
			}
			tr.releaseAll(t)
			d.hookWG.Wait()
			if zs := state.GetZone(domain); zs.PendingPublication {
				t.Fatal("the single invocation must confirm the generation")
			}
			// Nothing pending now: further cycles start nothing.
			d.signAllZones()
			d.hookWG.Wait()
			if n := tr.starts(t, ""); n != 1 {
				t.Fatalf("no further invocation without a new generation, got %d", n)
			}
		})
	}
}

// Simultaneous hook processes never exceed the bound; every zone is still
// deployed exactly once and confirmed.
func TestRDAYBLUEX018_ConcurrencyBound(t *testing.T) {
	setHookConcurrency(t, 2)
	d, cfg, state, domains := multiZoneDaemon(t, 8)
	tr := newHookTrace(t, false)
	cfg.Hooks.PostSignCmd = tr.cmd(0, 150*time.Millisecond)

	d.signAllZones()
	d.hookWG.Wait()
	if got := tr.maxOverlap(t); got > 2 {
		t.Fatalf("at most 2 hook processes may run at once, observed %d", got)
	}
	for _, domain := range domains {
		if n := tr.starts(t, domain); n != 1 {
			t.Fatalf("%s must be deployed exactly once, got %d", domain, n)
		}
		if state.GetZone(domain).PendingPublication {
			t.Fatalf("%s must be confirmed", domain)
		}
	}
	if w := d.hooks.runningWorkers(); w != 0 {
		t.Fatalf("workers must exit when the queue drains, got %d", w)
	}
}

// A failed generation is retried only after it completed AND its backoff
// elapsed; a changed hook command is retried at once.
func TestRDAYBLUEX018_FailureRetriesAfterBackoff(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	cfg.PollInterval = config.Duration{Duration: 400 * time.Millisecond} // backoff base
	tr := newHookTrace(t, false)
	cfg.Hooks.PostSignCmd = tr.cmd(1, 0)

	d.signAllZones() // attempt 1 fails
	d.hookWG.Wait()
	if n := tr.starts(t, ""); n != 1 {
		t.Fatalf("first attempt expected, got %d", n)
	}
	if !state.GetZone(domain).PendingPublication || !hasErrorPrefix(state.GetZone(domain).Errors, statepkg.OpDeployment) {
		t.Fatal("the failure must leave the zone pending with a deployment error")
	}
	// Immediately again: within the backoff, no retry.
	d.signAllZones()
	d.hookWG.Wait()
	if n := tr.starts(t, ""); n != 1 {
		t.Fatalf("a retry inside the backoff window must not start, got %d starts", n)
	}
	// After the base backoff: attempt 2.
	time.Sleep(450 * time.Millisecond)
	d.signAllZones()
	d.hookWG.Wait()
	if n := tr.starts(t, ""); n != 2 {
		t.Fatalf("after the backoff the generation is retried once, got %d starts", n)
	}
	// Backoff doubled: 450 ms later is still inside the 800 ms window.
	time.Sleep(450 * time.Millisecond)
	d.signAllZones()
	d.hookWG.Wait()
	if n := tr.starts(t, ""); n != 2 {
		t.Fatalf("the doubled backoff must still hold, got %d starts", n)
	}
	// The operator fixes the hook: a changed command is retried at once and
	// confirms.
	cfg.Hooks.PostSignCmd = tr.cmd(0, 0)
	d.signAllZones()
	d.hookWG.Wait()
	if n := tr.starts(t, ""); n != 3 {
		t.Fatalf("a changed hook command must be retried immediately, got %d starts", n)
	}
	if zs := state.GetZone(domain); zs.PendingPublication || hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("the successful retry confirms and clears the error: %+v", zs)
	}
}

// A newer generation supersedes a still-queued older generation of the same
// zone; the running one finishes and its completion cannot confirm the newer
// generation.
func TestRDAYBLUEX018_NewerGenerationSupersedesQueued(t *testing.T) {
	setHookConcurrency(t, 1)
	d, cfg, state, domains := multiZoneDaemon(t, 2)
	tr := newHookTrace(t, true)
	cfg.Hooks.PostSignCmd = tr.cmd(0, 0)
	a, b := domains[0], domains[1]

	d.signAllZones() // A's hook runs and blocks; B's is queued behind it
	tr.waitStarts(t, 1)
	if tr.starts(t, "") != 1 || d.hooks.queued() != 1 {
		t.Fatalf("one running, one queued expected; starts=%d queued=%d", tr.starts(t, ""), d.hooks.queued())
	}
	genB1 := state.GetZone(b).LastSigned

	// B is re-signed while B@1 is still queued: B@1 is dropped.
	appendZoneRecord(t, cfg.Zones[b].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones()
	genB2 := state.GetZone(b).LastSigned
	if !genB2.After(genB1) {
		t.Fatal("B must have been re-signed")
	}
	if q := d.hooks.queued(); q != 1 {
		t.Fatalf("the superseded B generation must be dropped from the queue, leaving 1, got %d", q)
	}

	tr.releaseAll(t)
	d.hookWG.Wait()
	if n := tr.starts(t, b); n != 1 {
		t.Fatalf("B must be deployed exactly once (its newest generation), got %d", n)
	}
	zb := state.GetZone(b)
	if zb.PendingPublication || !zb.PublishedGenerationSignedAt.Equal(genB2) {
		t.Fatalf("exactly B's newest generation is confirmed: %+v", zb)
	}
	if za := state.GetZone(a); za.PendingPublication {
		t.Fatalf("A is confirmed by its own completion: %+v", za)
	}
}

// Shutdown with work queued stays bounded: the daemon's hook wait returns
// within its timeout while a hook is still blocked, and the queued work is
// drained (not lost) once the hook releases.
func TestRDAYBLUEX018_ShutdownBoundedWithQueuedWork(t *testing.T) {
	setHookConcurrency(t, 1)
	d, cfg, _, _ := multiZoneDaemon(t, 3)
	tr := newHookTrace(t, true)
	cfg.Hooks.PostSignCmd = tr.cmd(0, 0)
	d.signAllZones() // one running (blocked), two queued
	tr.waitStarts(t, 1)
	if d.hooks.queued() != 2 {
		t.Fatalf("two zones must be queued, got %d", d.hooks.queued())
	}
	d.cancel()
	start := time.Now()
	d.waitForHooks(300 * time.Millisecond)
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("the shutdown wait must stay bounded, took %s", elapsed)
	}
	tr.releaseAll(t)
	d.hookWG.Wait()
	if n := tr.starts(t, ""); n != 3 {
		t.Fatalf("queued deployments drain once the blocking hook releases, got %d starts", n)
	}
}

// Coalesced mode: a batch never includes a zone whose generation is already
// running; the batch identity is its members.
func TestRDAYBLUEX018_CoalescedBatchExcludesInFlight(t *testing.T) {
	setHookConcurrency(t, 1)
	d, cfg, _, domains := multiZoneDaemon(t, 2)
	cfg.Hooks.CoalescePostSign = true
	tr := newHookTrace(t, true)
	cfg.Hooks.PostSignCmd = tr.cmd(0, 0)
	a, b := domains[0], domains[1]

	d.signAllZones() // one batch [A B] running (blocked)
	tr.waitStarts(t, 1)
	// B is re-signed: a new batch [B@2] is queued; A (running) is excluded.
	appendZoneRecord(t, cfg.Zones[b].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones()
	tr.releaseAll(t)
	d.hookWG.Wait()
	ev := tr.events(t)
	var batches []string
	for _, e := range ev {
		if e.kind == "start" {
			batches = append(batches, e.domain)
		}
	}
	if len(batches) != 2 {
		t.Fatalf("expected the initial batch and one follow-up batch, got %v", batches)
	}
	if batches[0] != a+" "+b && batches[0] != b+" "+a {
		t.Fatalf("first batch must name both zones, got %q", batches[0])
	}
	if batches[1] != b {
		t.Fatalf("the follow-up batch must exclude the running zone and name only the re-signed one, got %q", batches[1])
	}
}
