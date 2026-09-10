package main

import (
	"fmt"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
)

// Bounded, single-flight dispatch of the daemon's asynchronous post-sign hooks
// (RDAYBLUEX-018).
//
// Before this, every signed zone (and every pending retry, every cycle)
// started its own goroutine and child process with no bound and no memory of
// what was already running: a poll interval shorter than a hook's duration
// made the same deployment overlap itself, and a large zone set multiplied
// that into a process storm. The dispatcher:
//
//   - runs at most hookMaxConcurrent hook processes at a time, process-wide;
//   - single-flights each exact publication generation (domain + signed
//     timestamp, or the members of a coalesced batch): a generation that is
//     queued or running is not enqueued again;
//   - lets a newer generation of a zone supersede the zone's still-queued
//     older generation (a running one finishes; its completion is discarded
//     by the generation-aware callback, RDAYBLUEX-005);
//   - after a failure, makes the same generation eligible again only after a
//     bounded exponential backoff, unless the hook command itself changed;
//   - drains its queue on shutdown within the daemon's existing bounded wait
//     (workers are tracked on the daemon's hook wait group).
//
// The CLI still runs hooks synchronously through firePostSignHooks.

var (
	// hookMaxConcurrent bounds simultaneous asynchronous hook processes. A
	// deployment hook is typically `nsd-control reload`; running many at once
	// only contends for the nameserver. Package variable so tests can lower it.
	hookMaxConcurrent = 4
	// hookRetryBackoffMax caps the exponential backoff applied to a failing
	// generation's retries (the base is the daemon's poll interval).
	hookRetryBackoffMax = time.Hour
)

// hookIdentity is the single-flight key of one publication generation.
type hookIdentity struct {
	domain   string
	signedAt int64 // UnixNano
}

func identityOf(z SignedZoneRef) hookIdentity {
	return hookIdentity{domain: z.Domain, signedAt: z.SignedAt.UnixNano()}
}

// hookJob is one queued or running invocation set: the zones it deploys and
// the contract to deploy them under. The invocation itself (batch or per
// zone) is built when the job starts, so a queued job can still lose zones a
// newer generation superseded.
type hookJob struct {
	hooks     *config.HooksConfig
	outputDir string
	zones     []SignedZoneRef
	onDone    func([]SignedZoneRef, error)
}

// hookBackoff records a failing generation's retry schedule.
type hookBackoff struct {
	attempts int
	until    time.Time
	cmdKey   string
}

type hookDispatcher struct {
	mu      sync.Mutex
	queue   []*hookJob
	active  map[hookIdentity]bool // queued or running
	backoff map[hookIdentity]hookBackoff
	// backoffBase is the first retry delay after a failure (the daemon's
	// poll interval, as passed to the latest dispatch); doubled per further
	// failure of the same generation up to hookRetryBackoffMax.
	backoffBase time.Duration
	workers     int
	wg          *sync.WaitGroup
	now         func() time.Time
}

func newHookDispatcher(wg *sync.WaitGroup) *hookDispatcher {
	return &hookDispatcher{
		active:  map[hookIdentity]bool{},
		backoff: map[hookIdentity]hookBackoff{},
		wg:      wg,
		now:     time.Now,
	}
}

// hookCmdKey identifies the configured hook command, so a changed command
// (the operator fixed the hook) is retried at once instead of waiting out a
// backoff earned by the old one.
func hookCmdKey(hooks *config.HooksConfig) string {
	return fmt.Sprintf("%v|%q|%v", hooks.PostSignCmd, hooks.PostSign, hooks.Shell)
}

// dispatch enqueues the deployment of signed under the hook contract and
// returns how many zones were actually enqueued. Zones whose generation is
// already queued/running, or in backoff after a failure of that same
// generation under the same hook command, are skipped for this cycle; a zone
// whose older generation is still queued has that older entry dropped.
// backoffBase is the first retry delay (the daemon passes its poll interval).
func (h *hookDispatcher) dispatch(hooks *config.HooksConfig, outputDir string, signed []SignedZoneRef, backoffBase time.Duration, onDone func([]SignedZoneRef, error)) int {
	if !hookConfigured(hooks) || len(signed) == 0 {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	cmdKey := hookCmdKey(hooks)
	if backoffBase > 0 {
		h.backoffBase = backoffBase
	}

	var accepted []SignedZoneRef
	for _, z := range signed {
		id := identityOf(z)
		if h.active[id] {
			slog.Debug("[HOOK] Generation already queued or running; not enqueued again", "domain", z.Domain, "generation_signed_at", z.SignedAt.Format(time.RFC3339Nano))
			continue
		}
		if b, ok := h.backoff[id]; ok && b.cmdKey == cmdKey && now.Before(b.until) {
			slog.Info("[HOOK] Generation is in retry backoff after a failed deployment", "domain", z.Domain, "attempts", b.attempts, "retry_after", b.until.Format(time.RFC3339))
			continue
		}
		// A newer generation supersedes the zone's queued (not running)
		// older generations.
		h.dropQueuedOlderLocked(z)
		h.active[id] = true
		accepted = append(accepted, z)
	}
	if len(accepted) == 0 {
		return 0
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].Domain < accepted[j].Domain })
	// One batch job when coalescing (its identity is its members); otherwise
	// one job per zone, so zones spread across workers and a still-queued
	// zone can be superseded individually.
	if hooks.CoalescePostSign {
		h.queue = append(h.queue, &hookJob{hooks: hooks, outputDir: outputDir, zones: accepted, onDone: onDone})
	} else {
		for _, z := range accepted {
			h.queue = append(h.queue, &hookJob{hooks: hooks, outputDir: outputDir, zones: []SignedZoneRef{z}, onDone: onDone})
		}
	}
	for h.workers < hookMaxConcurrent && h.workers < len(h.queue) {
		h.workers++
		h.wg.Add(1)
		go h.worker()
	}
	return len(accepted)
}

// dropQueuedOlderLocked removes from queued jobs every entry for z's domain
// with an older generation; a job left with no zones is removed.
func (h *hookDispatcher) dropQueuedOlderLocked(z SignedZoneRef) {
	kept := h.queue[:0]
	for _, job := range h.queue {
		zones := job.zones[:0:0]
		for _, q := range job.zones {
			if q.Domain == z.Domain && q.SignedAt.Before(z.SignedAt) {
				delete(h.active, identityOf(q))
				slog.Info("[HOOK] Queued deployment superseded by a newer generation", "domain", q.Domain, "superseded_generation", q.SignedAt.Format(time.RFC3339Nano))
				continue
			}
			zones = append(zones, q)
		}
		job.zones = zones
		if len(zones) > 0 {
			kept = append(kept, job)
		}
	}
	h.queue = kept
}

// purgeQueued drops every queued (not running) job: after a configuration
// reload the new generation's first cycle re-derives what to deploy, and a
// completion from before the reload is discarded anyway (RDAYBLUEX-005).
func (h *hookDispatcher) purgeQueued() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, job := range h.queue {
		for _, z := range job.zones {
			delete(h.active, identityOf(z))
		}
	}
	h.queue = nil
}

// queued and running report the dispatcher's occupancy (for tests and logs).
func (h *hookDispatcher) queued() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, job := range h.queue {
		n += len(job.zones)
	}
	return n
}

func (h *hookDispatcher) runningWorkers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.workers
}

// worker drains the queue one job at a time and exits when it is empty.
func (h *hookDispatcher) worker() {
	defer h.wg.Done()
	for {
		h.mu.Lock()
		if len(h.queue) == 0 {
			h.workers--
			h.mu.Unlock()
			return
		}
		job := h.queue[0]
		h.queue = h.queue[1:]
		h.mu.Unlock()
		h.run(job)
	}
}

// run executes one job under the hook contract (one batch invocation, or one
// invocation per zone, sequentially) and settles its identities.
func (h *hookDispatcher) run(job *hookJob) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[HOOK] Panic in post-sign hook dispatch", "panic", r)
			h.settle(job.hooks, job.zones, fmt.Errorf("hook dispatch panicked: %v", r))
		}
	}()
	_, _, identity, _ := hookCmd(job.hooks)
	for _, inv := range buildHookInvocations(job.hooks, job.outputDir, job.zones) {
		err := runHookInvocation(job.hooks, identity, inv, io.Discard, job.onDone)
		h.settle(job.hooks, inv.zones, err)
	}
}

// settle clears the identities of a completed invocation and records or
// clears their backoff.
func (h *hookDispatcher) settle(hooks *config.HooksConfig, zones []SignedZoneRef, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := h.now()
	for _, z := range zones {
		id := identityOf(z)
		delete(h.active, id)
		if err == nil {
			delete(h.backoff, id)
			continue
		}
		b := h.backoff[id]
		b.attempts++
		b.cmdKey = hookCmdKey(hooks)
		delay := h.backoffBase
		if delay <= 0 {
			delay = time.Second
		}
		for i := 1; i < b.attempts && delay < hookRetryBackoffMax; i++ {
			delay *= 2
		}
		if delay > hookRetryBackoffMax {
			delay = hookRetryBackoffMax
		}
		b.until = now.Add(delay)
		h.backoff[id] = b
	}
}
