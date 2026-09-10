package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
)

// RegisterHealthHandlersWithDaemon registers health check endpoints with daemon
// liveness checks. The handlers resolve cfg/state per request via daemon.current()
// so they reflect a SIGHUP reload rather than the pointers captured at startup
// (R-006). daemon must be non-nil.
func RegisterHealthHandlersWithDaemon(mux *http.ServeMux, daemon *Daemon) {
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setSecurityHeaders(w)
		cfg, state := daemon.current()
		if !daemon.allowHealthRequest(cfg) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many health requests", http.StatusTooManyRequests)
			return
		}
		healthHandler(w, r, state, cfg, daemon)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		setSecurityHeaders(w)
		cfg, state := daemon.current()
		if !daemon.allowHealthRequest(cfg) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many health requests", http.StatusTooManyRequests)
			return
		}
		healthzHandler(w, r, state, cfg, daemon)
	})
}

// setSecurityHeaders adds standard security headers to responses
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
}

// healthHandler returns detailed health status
func healthHandler(w http.ResponseWriter, r *http.Request, state *statepkg.State, cfg *config.Config, daemon *Daemon) {
	status := buildStatusOutput(state, configuredZones(cfg)...)

	// Check if any zones have errors
	healthy := status.Summary.Errors == 0

	// Check directory dependencies (bounded probes, RDAYBLUEX-035)
	var depErrors []string
	if err := probeDir(daemon, cfg.OutputDir); err != nil {
		depErrors = append(depErrors, "output_dir: "+err.Error())
		healthy = false
	}
	if err := probeDir(daemon, cfg.DataDir); err != nil {
		depErrors = append(depErrors, "data_dir: "+err.Error())
		healthy = false
	}
	if err := probeDir(daemon, cfg.KeysDir()); err != nil {
		depErrors = append(depErrors, "keys_dir: "+err.Error())
		healthy = false
	}

	// Check signing loop liveness
	signingLoopAlive := true
	if daemon != nil {
		// RA6X-026: a cycle that could not load the authoritative state is a
		// persistent operational failure until the file is repaired.
		if fault := daemon.StateFault(); fault != "" {
			depErrors = append(depErrors, "state: "+fault)
			healthy = false
		}
		if daemon.signingLoopDead.Load() {
			depErrors = append(depErrors, "signing_loop: goroutine has exited")
			healthy = false
			signingLoopAlive = false
		}
		lastRun := daemon.lastSigningRun.Load()
		if lastRun > 0 {
			staleness := time.Since(time.Unix(lastRun, 0))
			// If the signing loop hasn't run in 3x the poll interval, something is wrong
			if staleness > 3*cfg.PollInterval.Duration {
				depErrors = append(depErrors, fmt.Sprintf("signing_loop: last ran %s ago (expected every %s)", staleness.Round(time.Second), cfg.PollInterval.String()))
				healthy = false
				signingLoopAlive = false
			}
		}
	}

	// Check for expired signatures
	var expiredZones []string
	now := time.Now()
	for domain, zone := range status.Zones {
		if !zone.SignaturesExp.IsZero() && now.After(zone.SignaturesExp) {
			expiredZones = append(expiredZones, domain)
			healthy = false
		}
	}
	if len(expiredZones) > 0 {
		depErrors = append(depErrors, fmt.Sprintf("expired_signatures: %v", expiredZones))
	}

	// RA6X-033: readiness covers every CONFIGURED zone, not only the ones that
	// made it into state. A configured zone with no state entry never
	// initialized; a zone that never produced a signed generation, or whose
	// generation was never confirmed served, is not ready either.
	for _, problem := range unreadyZones(cfg, state) {
		depErrors = append(depErrors, problem)
		healthy = false
	}

	w.Header().Set("Content-Type", "application/json")
	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	response := struct {
		Status           string        `json:"status"`
		Summary          StatusSummary `json:"summary"`
		SigningLoopAlive bool          `json:"signing_loop_alive"`
		ExpiredZones     []string      `json:"expired_zones,omitempty"`
		DepErrors        []string      `json:"dependency_errors,omitempty"`
	}{
		Status:           "healthy",
		Summary:          status.Summary,
		SigningLoopAlive: signingLoopAlive,
		ExpiredZones:     expiredZones,
		DepErrors:        depErrors,
	}

	if !healthy {
		response.Status = "unhealthy"
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Debug("[HEALTH] Failed to encode response", "error", err)
	}
}

// healthzHandler returns simple OK for kubernetes probes
func healthzHandler(w http.ResponseWriter, r *http.Request, state *statepkg.State, cfg *config.Config, daemon *Daemon) {
	status := buildStatusOutput(state, configuredZones(cfg)...)
	healthy := status.Summary.Errors == 0

	// Check directory dependencies (bounded probes, RDAYBLUEX-035)
	if err := probeDir(daemon, cfg.OutputDir); err != nil {
		healthy = false
	}
	if err := probeDir(daemon, cfg.DataDir); err != nil {
		healthy = false
	}

	// Check signing loop liveness
	if daemon != nil {
		if daemon.StateFault() != "" {
			healthy = false
		}
		if daemon.signingLoopDead.Load() {
			healthy = false
		}
		lastRun := daemon.lastSigningRun.Load()
		if lastRun > 0 && time.Since(time.Unix(lastRun, 0)) > 3*cfg.PollInterval.Duration {
			healthy = false
		}
	}

	// Check for expired signatures
	now := time.Now()
	for _, zone := range status.Zones {
		if !zone.SignaturesExp.IsZero() && now.After(zone.SignaturesExp) {
			healthy = false
			break
		}
	}
	if len(unreadyZones(cfg, state)) > 0 {
		healthy = false
	}

	if !healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
		if _, err := w.Write([]byte("UNHEALTHY")); err != nil {
			slog.Debug("[HEALTH] Failed to write response", "error", err)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		slog.Debug("[HEALTH] Failed to write response", "error", err)
	}
}

// Health probe bounding (RDAYBLUEX-035). Each health request used to create
// and delete temporary files in the output, data and keys directories, so a
// reachable client — or an aggressive orchestrator — could drive sustained
// write/journal/inode churn on the filesystems that hold state, keys and
// signed output. The write probes are now single-flighted and their results
// cached for healthProbeInterval; the cache is invalidated on a configuration
// reload and whenever a real signing or state write fails, so a genuine
// failure is reported at once. When the listener is deliberately exposed
// (health.allow_remote), requests are additionally rate limited.

var (
	// healthProbeInterval is how long one directory probe result is served;
	// shorter than any operational alert tolerance. Package variable so tests
	// can shorten it.
	healthProbeInterval = 10 * time.Second
	// dirProbeFn performs the real write probe; a test seam.
	dirProbeFn = checkDirWritable
	// healthRemoteRate/Burst bound remote health requests per daemon.
	healthRemoteRate  = 20.0
	healthRemoteBurst = 40.0
)

// dirProbeCache single-flights and caches directory write probes.
type dirProbeCache struct {
	mu      sync.Mutex
	entries map[string]*dirProbeEntry
}

type dirProbeEntry struct {
	err      error
	at       time.Time
	inflight chan struct{}
}

func newDirProbeCache() *dirProbeCache {
	return &dirProbeCache{entries: map[string]*dirProbeEntry{}}
}

// probe returns the cached probe result for dir when it is fresh, joins a
// probe already in flight, or runs one probe for every concurrent caller.
func (c *dirProbeCache) probe(dir string) error {
	c.mu.Lock()
	e := c.entries[dir]
	if e == nil {
		e = &dirProbeEntry{}
		c.entries[dir] = e
	}
	if e.inflight == nil && !e.at.IsZero() && time.Since(e.at) < healthProbeInterval {
		err := e.err
		c.mu.Unlock()
		return err
	}
	if e.inflight != nil {
		done := e.inflight
		c.mu.Unlock()
		<-done
		c.mu.Lock()
		err := e.err
		c.mu.Unlock()
		return err
	}
	done := make(chan struct{})
	e.inflight = done
	c.mu.Unlock()

	err := dirProbeFn(dir)

	c.mu.Lock()
	// A probe completing after an invalidation stores into the fresh entry
	// only if it is still the one registered for the directory.
	if cur := c.entries[dir]; cur == e {
		e.err, e.at, e.inflight = err, time.Now(), nil
	}
	c.mu.Unlock()
	close(done)
	return err
}

// invalidate discards every cached result; in-flight probes complete and are
// not stored (a new probe runs on the next request).
func (c *dirProbeCache) invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = map[string]*dirProbeEntry{}
}

// healthLimiter is a small token bucket for remote health requests.
type healthLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (l *healthLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.last.IsZero() {
		l.tokens = healthRemoteBurst
	} else {
		l.tokens += now.Sub(l.last).Seconds() * healthRemoteRate
		if l.tokens > healthRemoteBurst {
			l.tokens = healthRemoteBurst
		}
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

// probeDir runs the bounded probe through the daemon's cache when there is a
// daemon (the served configuration), or a direct probe otherwise.
func probeDir(daemon *Daemon, dir string) error {
	if daemon == nil || daemon.healthProbes == nil {
		return dirProbeFn(dir)
	}
	return daemon.healthProbes.probe(dir)
}

// checkDirWritable verifies a directory exists and is actually writable by the
// daemon, by creating and immediately removing a temp file. Inspecting only the
// owner-write mode bit (the previous heuristic) gave false 503s for a
// group-writable directory the daemon can legitimately write — e.g. a
// root:daemon 0770 dir with the daemon user in the group, where the owner-write
// bit describes root, not the daemon (R-071). A temp create/remove is cheap
// enough for a health probe and reflects real writability.
func checkDirWritable(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	f, err := os.CreateTemp(dir, ".health-write-check-*")
	if err != nil {
		return fmt.Errorf("%s is not writable: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	if err := os.Remove(name); err != nil {
		slog.Warn("[HEALTH] failed to remove write-check temp file", "path", name, "error", err)
	}
	return nil
}

// unreadyZones reports every configured zone that has not produced a valid,
// deployed generation (RA6X-033): absent from state (initialization never
// succeeded), never signed, or signed but never confirmed served.
func unreadyZones(cfg *config.Config, state *statepkg.State) []string {
	var problems []string
	zones := state.SnapshotZones()
	names := make([]string, 0, len(cfg.Zones))
	for domain := range cfg.Zones {
		names = append(names, domain)
	}
	sort.Strings(names)
	for _, domain := range names {
		zs, ok := zones[domain]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("zone %s: configured but not initialized", domain))
		case zs.KSK == nil || zs.ZSK == nil:
			problems = append(problems, fmt.Sprintf("zone %s: key initialization has not succeeded", domain))
		case zs.LastSigned.IsZero():
			problems = append(problems, fmt.Sprintf("zone %s: never signed", domain))
		case zs.PendingPublication && zs.PublishedAt.IsZero():
			problems = append(problems, fmt.Sprintf("zone %s: signed but never confirmed served", domain))
		}
	}
	return problems
}
