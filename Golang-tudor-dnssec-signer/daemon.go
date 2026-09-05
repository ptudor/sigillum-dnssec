package main

import (
	"context"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"

	"github.com/ptudor/dnssec-tudor/internal/fsutil"
	"github.com/ptudor/dnssec-tudor/internal/metrics"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ptudor/dnssec-tudor/internal/config"
)

// Daemon manages the signing loop and optional web server
type Daemon struct {
	cfg       *config.Config
	state     *statepkg.State
	signer    *signerpkg.Signer
	rollover  *signerpkg.RolloverManager
	heartbeat *HeartbeatClient

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	hookWG sync.WaitGroup // tracks async post-sign hook goroutines (R-026)

	mu              sync.RWMutex
	server          *http.Server
	tickerReset     chan time.Duration // signals the signing loop to reset its ticker
	signingLoopDead atomic.Bool        // true if signing loop goroutine has exited
	lastSigningRun  atomic.Int64       // unix timestamp of last signing loop iteration
	// stateFault holds the reason the authoritative state could not be loaded
	// in the most recent signing cycle ("" when healthy). While set, signing
	// cycles are skipped and readiness reports the failure (RA6X-026).
	stateFault atomic.Pointer[string]
	// ready is closed once Run has bound its listeners, started the heartbeat
	// and registered its workers. Reload waits for it, so a SIGHUP during
	// startup cannot race the startup reads of cfg/heartbeat (RA6X-040).
	ready     chan struct{}
	readyOnce sync.Once
	starting  atomic.Bool // Run has begun its startup sequence
	// lastSaveFailed records that the previous cycle could not persist its
	// results, so the next cycle merges rather than adopting the disk state
	// wholesale (RA6X-025: newer unsaved signing results are never replaced
	// by older disk data).
	lastSaveFailed atomic.Bool
}

// markReady publishes the ready lifecycle state (idempotent).
func (d *Daemon) markReady() {
	d.readyOnce.Do(func() { close(d.ready) })
}

// setStateFault records (or clears, with "") the persistent state-load failure.
func (d *Daemon) setStateFault(msg string) {
	d.stateFault.Store(&msg)
}

// StateFault returns the current state-load failure, or "" when healthy.
func (d *Daemon) StateFault() string {
	if p := d.stateFault.Load(); p != nil {
		return *p
	}
	return ""
}

// NewDaemon creates a new daemon instance
func NewDaemon(cfg *config.Config, state *statepkg.State) *Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		cfg:         cfg,
		state:       state,
		signer:      signerpkg.NewSigner(cfg, state),
		rollover:    signerpkg.NewRolloverManager(cfg, state),
		heartbeat:   NewHeartbeatClient(&cfg.Heartbeat),
		ctx:         ctx,
		cancel:      cancel,
		tickerReset: make(chan time.Duration, 1),
		ready:       make(chan struct{}),
	}
}

// Run starts the daemon's main loop
func (d *Daemon) Run() (err error) {
	slog.Info("[DAEMON] starting")
	d.starting.Store(true)

	// A startup that fails, or that finds shutdown already requested, must
	// wake any Reload waiting for readiness and never start a worker
	// afterwards (RA6X-040).
	defer func() {
		if err != nil {
			d.cancel()
		}
		d.markReady()
	}()

	// Every startup reference to state a Reload may swap goes through ONE
	// guarded snapshot (RA6X-040); Reload itself waits for readiness, so the
	// snapshot is also what the workers start from.
	snap := d.takeSnapshot()

	// Ensure directories exist
	if err := d.ensureDirectories(snap.cfg); err != nil {
		return err
	}

	// Validate startup requirements
	if err := d.validateStartup(snap.cfg); err != nil {
		return fmt.Errorf("startup validation failed: %w", err)
	}

	// Bind the listeners before starting anything else. A failed initial bind is
	// a startup failure, not a warning: return it from Run() so the process
	// exits non-zero. Together with the instance lock taken in runServe this
	// refuses a second `serve` (R-021, RA6X-006).
	healthAddr := snap.cfg.Health.Listen
	webEnabled := snap.cfg.Web.Enabled
	webAddr := snap.cfg.Web.Listen

	healthLn, err := net.Listen("tcp", healthAddr)
	if err != nil {
		return fmt.Errorf("health listen %s: %w", healthAddr, err)
	}

	var webLn net.Listener
	if webEnabled {
		webLn, err = net.Listen("tcp", webAddr)
		if err != nil {
			healthLn.Close()
			return fmt.Errorf("web listen %s: %w", webAddr, err)
		}
	}

	// Shutdown may already have been requested while we were binding: do not
	// start the heartbeat or any worker on a cancelled daemon (RA6X-040).
	select {
	case <-d.ctx.Done():
		healthLn.Close()
		if webLn != nil {
			webLn.Close()
		}
		slog.Info("[DAEMON] shutdown requested during startup; nothing started")
		return nil
	default:
	}

	// Start heartbeat monitoring only once the ports are secured, using the
	// client captured in the snapshot (Reload cannot have swapped it yet).
	snap.heartbeat.Start()

	// Start web server if enabled
	if webLn != nil {
		d.wg.Add(1)
		go d.runWebServer(webLn)
	}

	// Start health server (always on a separate internal port)
	d.wg.Add(1)
	go d.runHealthServer(healthLn)

	// Main signing loop
	d.wg.Add(1)
	go d.runSigningLoop()

	// Workers are registered and the heartbeat is running: publish readiness
	// so a pending Reload may proceed.
	d.markReady()

	// Wait for shutdown
	<-d.ctx.Done()
	d.wg.Wait()

	// Wait (bounded) for any in-flight post-sign hook goroutines to finish, so a
	// shutdown right after a signing cycle doesn't kill the final coalesced
	// nsd-control reload before it runs (R-026).
	d.waitForHooks(30 * time.Second)

	slog.Info("[DAEMON] stopped")
	return nil
}

// waitForHooks blocks until all tracked post-sign hook goroutines finish or the
// timeout elapses, whichever comes first. Called after the signing loop has
// exited, so no new hooks can be started while we wait.
func (d *Daemon) waitForHooks(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		d.hookWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("[DAEMON] Timed out waiting for post-sign hooks to finish", "timeout", timeout.String())
	}
}

// Shutdown gracefully stops the daemon
func (d *Daemon) Shutdown() {
	slog.Info("[DAEMON] Initiating graceful shutdown")

	// Cancel first so a Run still in its startup sequence stops before it
	// starts any worker or heartbeat, then stop the heartbeat client read
	// under the lock (Reload may have swapped it) (RA6X-040).
	d.cancel()
	d.mu.RLock()
	hb := d.heartbeat
	d.mu.RUnlock()
	hb.Stop()

	// R-016: snapshot the server pointer and timeout under the lock, then RELEASE the
	// lock BEFORE the blocking server.Shutdown. That call waits for in-flight handlers
	// to return, and those handlers still need d.current()'s RLock — holding d.mu
	// across the wait would deadlock every graceful stop until the context expires.
	d.mu.Lock()
	server := d.server
	shutdownTimeout := d.cfg.Health.ShutdownTimeout.Duration
	d.mu.Unlock()

	if server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		// http.Server.Shutdown is itself idempotent, so a repeated/concurrent
		// Shutdown is safe.
		if err := server.Shutdown(ctx); err != nil {
			slog.Warn("[DAEMON] Error during server shutdown", "error", err)
		}
	}
}

// Reload updates the daemon's configuration and state. It waits until Run has
// published its ready lifecycle state so startup never races a swap, and is a
// no-op once shutdown has begun (RA6X-040).
func (d *Daemon) Reload(cfg *config.Config, state *statepkg.State) {
	// Only a startup that is actually in progress is serialized against; a
	// daemon whose Run has not begun has no startup reads to race.
	if d.starting.Load() {
		select {
		case <-d.ready:
		case <-d.ctx.Done():
		}
	}
	if d.ctx.Err() != nil {
		slog.Info("[DAEMON] Ignoring reload: daemon is shutting down or failed to start")
		return
	}
	d.mu.Lock()
	oldCfg := d.cfg
	oldHeartbeat := d.heartbeat
	newHeartbeat := NewHeartbeatClient(&cfg.Heartbeat)

	d.cfg = cfg
	d.state = state
	d.signer = signerpkg.NewSigner(cfg, state)
	d.rollover = signerpkg.NewRolloverManager(cfg, state)
	d.heartbeat = newHeartbeat
	d.mu.Unlock()

	// Stop the old client and start the new one outside the lock. Both Stop()
	// and Start() send a synchronous heartbeat with up to a 10s HTTP timeout;
	// holding d.mu across that I/O would stall takeSnapshot() and the signing
	// loop for up to ~20s on a blackholed endpoint (R-018).
	oldHeartbeat.Stop()
	newHeartbeat.Start()

	// Reset signing loop ticker if poll interval changed. Drain any pending
	// (older) reset first, then send the newest interval, so two rapid SIGHUPs
	// leave the ticker on the LATEST interval rather than keeping the first and
	// dropping the second (R-057). Reload is serialized (single signal
	// goroutine) and the ticker consumer is alive during reload, so the send
	// after draining cannot block.
	if cfg.PollInterval.Duration != oldCfg.PollInterval.Duration {
		select {
		case <-d.tickerReset:
		default:
		}
		d.tickerReset <- cfg.PollInterval.Duration
		slog.Info("[DAEMON] Poll interval updated", "old", oldCfg.PollInterval.String(), "new", cfg.PollInterval.String())
	}

	// A changed output directory is reconciled now: the destination is created
	// (or the failure surfaced) and every zone's output is found missing there
	// on the next cycle, which regenerates it; the previous directory's files
	// are left in place for whatever still serves them (RA6X-035).
	if oldCfg.OutputDir != cfg.OutputDir {
		if err := signerpkg.EnsureDir(cfg.OutputDir); err != nil {
			slog.Error("[DAEMON] Output directory changed but cannot be created; signed zones cannot be published there until it is fixed",
				"old", oldCfg.OutputDir, "new", cfg.OutputDir, "error", err)
		} else {
			slog.Info("[DAEMON] Output directory changed; signed zones will be regenerated there on the next cycle",
				"old", oldCfg.OutputDir, "new", cfg.OutputDir)
		}
	}

	// Warn if listen addresses changed (requires restart)
	if oldCfg.Web.Listen != cfg.Web.Listen || oldCfg.Web.Enabled != cfg.Web.Enabled {
		slog.Warn("[DAEMON] Web listen address changed; restart required to take effect",
			"old", oldCfg.Web.Listen, "new", cfg.Web.Listen)
	}
	if oldCfg.Health.Listen != cfg.Health.Listen {
		slog.Warn("[DAEMON] Health listen address changed; restart required to take effect",
			"old", oldCfg.Health.Listen, "new", cfg.Health.Listen)
	}

	slog.Info("[DAEMON] Configuration and state reloaded", "zones", len(cfg.Zones))
}

func (d *Daemon) ensureDirectories(cfg *config.Config) error {
	// Data and output dirs need standard permissions
	for _, dir := range []string{cfg.DataDir, cfg.OutputDir} {
		if err := signerpkg.EnsureDir(dir); err != nil {
			return err
		}
	}
	// Keys directory holds private keys — restrict to owner-only
	if err := signerpkg.EnsureDirSecure(cfg.KeysDir()); err != nil {
		return err
	}
	return nil
}

// validateStartup performs startup checks to ensure the daemon can operate correctly
func (d *Daemon) validateStartup(cfg *config.Config) error {
	// Verify output_dir is writable
	if err := d.checkDirWritable(cfg.OutputDir, "output_dir"); err != nil {
		return err
	}

	// Verify data_dir is writable
	if err := d.checkDirWritable(cfg.DataDir, "data_dir"); err != nil {
		return err
	}

	// Verify keys_dir is writable (with secure permissions)
	keysDir := cfg.KeysDir()
	if err := d.checkDirWritable(keysDir, "keys_dir"); err != nil {
		return err
	}

	// Verify the state file is accessible WITHOUT writing it (RA6X-006): a
	// startup snapshot written here could overwrite a state a concurrent CLI
	// command or an already-running daemon committed after we loaded ours,
	// and it happens before the ports are bound, so even a duplicate daemon
	// that then fails to start would have clobbered live state. Writability
	// of data_dir was checked above; an existing file must merely be
	// openable for writing.
	if err := checkStateFileAccessible(cfg.StatePath()); err != nil {
		return fmt.Errorf("cannot access state file: %w", err)
	}

	slog.Debug("[DAEMON] Startup validation passed")
	return nil
}

// checkStateFileAccessible verifies an existing state file can be opened for
// writing without truncating or modifying it; a missing file is fine (the
// first Save creates it in the already-checked data_dir).
func checkStateFileAccessible(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.Close()
}

// checkDirWritable verifies a directory is writable by creating and removing a
// unique temporary file. It must never open, truncate, or remove a pre-existing
// fixed-name path: the previous ".startup_check" (os.Create = create-or-truncate)
// would destroy any operator/tooling file of that name on every startup (R-041).
func (d *Daemon) checkDirWritable(dir, name string) error {
	f, err := os.CreateTemp(dir, ".startup_check-*")
	if err != nil {
		return fmt.Errorf("%s not writable (%s): %w", name, dir, err)
	}
	testFile := f.Name()
	if err := f.Close(); err != nil {
		os.Remove(testFile)
		return fmt.Errorf("%s writability probe close failed (%s): %w", name, dir, err)
	}
	if err := os.Remove(testFile); err != nil {
		return fmt.Errorf("%s writability probe cleanup failed (%s): %w", name, dir, err)
	}
	return nil
}

func (d *Daemon) runSigningLoop() {
	defer d.wg.Done()
	defer d.signingLoopDead.Store(true)

	// The initial interval comes from a guarded snapshot; Reload may swap
	// d.cfg concurrently (RA6X-040).
	ticker := time.NewTicker(d.takeSnapshot().cfg.PollInterval.Duration)
	defer ticker.Stop()

	// Initial sign
	d.signAllZonesSafe()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.signAllZonesSafe()
		case newInterval := <-d.tickerReset:
			ticker.Reset(newInterval)
		}
	}
}

// signAllZonesSafe wraps signAllZones with panic recovery so the signing loop
// survives panics and continues on the next tick.
func (d *Daemon) signAllZonesSafe() {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[DAEMON] Panic in signing loop iteration (recovered, will retry next tick)", "panic", r)
		}
	}()
	d.signAllZones()
}

// snapshot captures all daemon references under a single lock for a signing cycle.
// This prevents races where a SIGHUP reload swaps pointers mid-cycle.
type snapshot struct {
	cfg       *config.Config
	state     *statepkg.State
	signer    *signerpkg.Signer
	rollover  *signerpkg.RolloverManager
	heartbeat *HeartbeatClient
}

func (d *Daemon) takeSnapshot() snapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return snapshot{
		cfg:       d.cfg,
		state:     d.state,
		signer:    d.signer,
		rollover:  d.rollover,
		heartbeat: d.heartbeat,
	}
}

// current returns the daemon's live config and state under the read lock. HTTP
// handlers call this per request so the web UI and health endpoints reflect a
// SIGHUP reload instead of serving the pointers captured at startup (R-006).
func (d *Daemon) current() (*config.Config, *statepkg.State) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cfg, d.state
}

func (d *Daemon) signAllZones() {
	snap := d.takeSnapshot()

	// Record that the signing loop is alive
	d.lastSigningRun.Store(time.Now().Unix())

	// Serialize the whole load-mutate-save span against mutating CLI commands (R-007). A
	// CLI write landing between our ReloadFromDisk and Save would otherwise be clobbered
	// by our whole-map Save, and a rollover started mid-cycle would be reverted. On
	// contention, skip this cycle (safe — the next poll retries) rather than crash.
	lock, err := acquireStateLock(snap.cfg.DataDir, 10*time.Second)
	if err != nil {
		slog.Warn("[DAEMON] Could not acquire state lock; skipping this signing cycle", "error", err)
		return
	}
	defer lock.release()

	// Reload state from disk to pick up any zones added by CLI commands. If
	// the authoritative state cannot be loaded or validated, fail this cycle
	// CLOSED (RA6X-026): signing on a stale in-memory snapshot could publish
	// a key set that a CLI transition has already moved past, and the final
	// Save would overwrite the newer/unreadable file with the stale snapshot.
	// Nothing is mutated; the failure is exposed via readiness and the read
	// is retried next cycle.
	//
	// Under the lock the disk is authoritative (RA6X-025): it holds every CLI
	// mutation since our last save, including ones the merge heuristics could
	// not see (warnings added/cleared, removals, phase metadata). Adopt it
	// wholesale — unless the previous cycle failed to persist its results, in
	// which case memory holds newer signing results that must not be replaced
	// by older disk data, and the merge is used instead.
	var reloadErr error
	if d.lastSaveFailed.Load() {
		reloadErr = snap.state.ReloadFromDisk()
	} else {
		reloadErr = snap.state.ReplaceFromDisk()
	}
	if reloadErr != nil {
		msg := fmt.Sprintf("authoritative state could not be loaded: %v", reloadErr)
		d.setStateFault(msg)
		slog.Error("[DAEMON] Skipping signing cycle: state on disk is unreadable or invalid; no zone, key or state file will be mutated until it is repaired", "error", reloadErr)
		return
	}
	d.setStateFault("")

	slog.Debug("[DAEMON] Checking zones for signing", "count", len(snap.cfg.Zones))

	// Track successfully-signed zones so we can fire one batched post-sign
	// hook at the end of the cycle when coalesce_post_sign is enabled.
	// With N=3000 zones, coalescing turns 3000 nsd-control reload calls
	// (one per zone) into exactly one, at the cost of losing the per-zone
	// DNSSEC_DOMAIN env var. Consumers get DNSSEC_DOMAINS (space-list) and
	// DNSSEC_BATCH_SIZE instead.
	var signedZones []SignedZoneRef
signLoop:
	for domain := range snap.cfg.Zones {
		// Stop promptly on shutdown rather than iterating every remaining zone
		// (each sign + heartbeat can take seconds). We still fall through to the
		// Save and coalesced hook below so the zones already signed this cycle
		// are persisted and their reload fires (R-019).
		select {
		case <-d.ctx.Done():
			slog.Info("[DAEMON] Shutdown requested; ending signing cycle early", "signed", len(signedZones))
			break signLoop
		default:
		}
		if d.checkAndSignZoneSafe(snap, domain) {
			signedZones = append(signedZones, signedRef(snap.cfg, domain, snap.cfg.Zones[domain].Path))
		}
	}

	// Check for automatic ZSK rollovers
rolloverLoop:
	for domain := range snap.cfg.Zones {
		select {
		case <-d.ctx.Done():
			break rolloverLoop
		default:
		}
		zoneState := snap.state.GetZone(domain)
		if zoneState == nil || zoneState.ZSK == nil {
			continue
		}
		if err := snap.rollover.CheckZSKRollover(domain); err != nil {
			if fsutil.IsCommitted(err) {
				slog.Warn("[ROLLOVER] ZSK rollover state saved but its durability across power loss is uncertain", "domain", domain, "error", err)
			} else {
				slog.Error("[ROLLOVER] ZSK rollover check failed", "domain", domain, "error", err)
			}
		}
	}

	// Defense-in-depth: re-reload immediately before Save to adopt any CLI write that
	// slipped in (the merge keeps our fresher-signed zones and adopts a disk zone whose
	// rollover differs — see ReloadFromDisk), then persist the merged whole map. If
	// the file became unreadable/invalid during the cycle, do NOT overwrite it with
	// our snapshot (RA6X-026): keep the disk evidence, surface the fault, and let the
	// next cycle retry. The signed output already written this cycle stays in place.
	if err := snap.state.ReloadFromDisk(); err != nil {
		msg := fmt.Sprintf("authoritative state could not be re-loaded before save: %v", err)
		d.setStateFault(msg)
		d.lastSaveFailed.Store(true)
		slog.Error("[DAEMON] Not saving state this cycle: state on disk is unreadable or invalid", "error", err)
	} else if err := snap.state.Save(); err != nil {
		if fsutil.IsCommitted(err) {
			// The state file is in place; only its durability is uncertain (RA6X-049).
			d.lastSaveFailed.Store(false)
			slog.Warn("[DAEMON] State saved but its durability across power loss is uncertain", "error", err)
		} else {
			d.lastSaveFailed.Store(true)
			slog.Error("[DAEMON] Failed to save state", "error", err)
		}
	} else {
		d.lastSaveFailed.Store(false)
	}

	// Fire the coalesced post-sign hook after state is saved — this way
	// any consumer that introspects state.json sees the just-signed zones.
	if snap.cfg.Hooks.CoalescePostSign && len(signedZones) > 0 {
		_ = firePostSignHooks(&snap.cfg.Hooks, snap.cfg.OutputDir, signedZones, &d.hookWG)
	}

	// Update Prometheus metrics
	metrics.UpdateZoneMetrics(snap.state)
}

// checkAndSignZoneSafe wraps checkAndSignZone with per-zone panic recovery
// so a panic in one zone doesn't prevent other zones from being signed.
// Returns true when the zone was signed this invocation so the caller can
// include it in a batched post-sign hook.
func (d *Daemon) checkAndSignZoneSafe(snap snapshot, domain string) (signed bool) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[DAEMON] Panic signing zone (recovered, other zones unaffected)", "domain", domain, "panic", r)
			signed = false
		}
	}()
	signed, err := d.checkAndSignZone(snap, domain)
	if err != nil {
		slog.Error("[DAEMON] Failed to sign zone", "domain", domain, "error", err)
	}
	return signed
}

func (d *Daemon) checkAndSignZone(snap snapshot, domain string) (bool, error) {
	zoneState := snap.state.GetZone(domain)

	// Check if zone needs signing
	zoneCfg := snap.cfg.Zones[domain]
	needsSign, reason := snap.signer.NeedsSign(domain, zoneCfg.Path, zoneState)
	if !needsSign {
		slog.Debug("[DAEMON] Zone does not need signing", "domain", domain, "path", zoneCfg.Path)
		return false, nil
	}

	slog.Info("[DAEMON] Signing zone", "domain", domain, "reason", reason)

	// Send heartbeat for signing start. Use the snapshot's client (captured
	// under the lock) rather than d.heartbeat, which Reload reassigns (R-018).
	snap.heartbeat.SigningStart(domain)

	// Initialize a zone that is absent, or present only as a keyless
	// placeholder from a prior failed init (e.g. written by a cron `sign` and
	// merged in via ReloadFromDisk) — but first try to recover existing key
	// files from disk. If key files already exist (e.g., state was lost but
	// keys survive), reuse them to preserve the DS chain of trust. Generating
	// new keys when a published DS still references the old key causes SERVFAIL.
	// Re-running the init branch for a placeholder (nil KSK/ZSK) mirrors
	// SignAll (R-033): the daemon heals it instead of erroring every cycle
	// until a CLI `sign` runs.
	if zoneState == nil {
		// RA6X-025: a zone a CLI `remove` took out of management after THIS
		// configuration was loaded is a stale entry, not a new zone; do not
		// re-create it from the old configuration. A configuration loaded after
		// the removal that still lists the zone means the operator re-added it.
		if removedAt, removed := snap.state.RemovedAt(domain); removed {
			if !snap.cfg.LoadedAt.After(removedAt) {
				slog.Info("[DAEMON] Zone was removed from management after this configuration was loaded; skipping until the configuration is reloaded",
					"domain", domain, "removed_at", removedAt.Format(time.RFC3339))
				return false, nil
			}
			snap.state.ClearRemoved(domain)
		}
	}
	if zoneState == nil || zoneState.KSK == nil || zoneState.ZSK == nil {
		keyGen := signerpkg.NewKeyGenerator(snap.cfg)
		ksk, zsk, err := signerpkg.RecoverOrGenerateKeys(keyGen, domain)
		if err != nil {
			return false, err
		}
		zoneState = &statepkg.ZoneState{
			Path: zoneCfg.Path,
			KSK:  ksk,
			ZSK:  zsk,
		}
		snap.state.SetZone(domain, zoneState)
	}

	// The active configuration is authoritative for the source path: SignZone
	// reads Signer.SourcePath (the configured path) and records it in state
	// only after a successful publication, so a failed or unparseable new path
	// leaves the prior signed output and source reference intact (RA6X-005).
	// Sign the zone
	signStart := time.Now()
	if err := snap.signer.SignZone(domain); err != nil {
		snap.state.Mutate(func() { zoneState.AddError(err.Error()) })
		metrics.RecordSigningOperation(domain, time.Since(signStart).Seconds(), false)
		snap.heartbeat.SigningError(domain)
		return false, err
	}

	// Clear errors on success and send completion heartbeat with the serial
	// actually served (differs from the unsigned serial under serial_policy
	// = "epoch")
	snap.state.Mutate(zoneState.ClearErrors)
	snap.heartbeat.SigningComplete(domain, zoneState.PublishedSerial)

	// Execute per-zone post-sign hook only when NOT coalescing — the caller
	// will fire one batched hook at end-of-cycle when coalesce is on.
	if !snap.cfg.Hooks.CoalescePostSign {
		_ = firePostSignHooks(&snap.cfg.Hooks, snap.cfg.OutputDir,
			[]SignedZoneRef{signedRef(snap.cfg, domain, zoneCfg.Path)}, &d.hookWG)
	}

	return true, nil
}

func (d *Daemon) runWebServer(ln net.Listener) {
	defer d.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[DAEMON] Panic in web server", "panic", r)
		}
	}()

	// Handlers resolve cfg/state per request via the Daemon so a SIGHUP reload
	// is reflected without a restart (R-006).
	srv := NewWebServer(d)

	d.mu.Lock()
	d.server = srv
	d.mu.Unlock()

	// If shutdown was already signalled before we got here, don't start serving
	// — Serve would otherwise run on an already-cancelled daemon with nothing to
	// stop it, and wg.Wait() would hang forever (R-020).
	select {
	case <-d.ctx.Done():
		ln.Close()
		return
	default:
	}

	// Shut the server down when the daemon context is cancelled. This mirrors
	// the health server's watcher and covers the window where Shutdown() ran
	// before d.server was stored. Calling Shutdown twice is safe (R-020).
	go func() {
		<-d.ctx.Done()
		d.mu.RLock()
		timeout := d.cfg.Health.ShutdownTimeout.Duration
		d.mu.RUnlock()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Debug("[WEB] Error during web server shutdown", "error", err)
		}
	}()

	slog.Info("[WEB] Starting server", "listen", srv.Addr)
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		slog.Error("[WEB] Server error", "error", err)
	}
}

func (d *Daemon) runHealthServer(ln net.Listener) {
	defer d.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[DAEMON] Panic in health server", "panic", r)
		}
	}()

	// Copy cfg fields into locals under the lock (R-018) — the goroutine must
	// not read d.cfg directly, which Reload reassigns.
	d.mu.RLock()
	debugVars := d.cfg.Health.DebugVars
	d.mu.RUnlock()

	// Health server runs on an internal port for monitoring. Handlers resolve
	// cfg/state per request via the Daemon so a reload is reflected (R-006).
	mux := http.NewServeMux()
	RegisterHealthHandlersWithDaemon(mux, d)
	mux.Handle("/metrics", promhttp.Handler())
	if debugVars {
		mux.Handle("/debug/vars", expvar.Handler())
		slog.Debug("[DAEMON] /debug/vars endpoint enabled")
	}

	server := &http.Server{
		Handler:           mux,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-d.ctx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			slog.Debug("[WEB] Error during health server shutdown", "error", err)
		}
	}()

	slog.Debug("[WEB] Starting health server", "listen", ln.Addr().String())
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		slog.Error("[WEB] Health server error", "error", err)
	}
}
