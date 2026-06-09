package main

import (
	"context"
	"expvar"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Daemon manages the signing loop and optional web server
type Daemon struct {
	cfg       *Config
	state     *State
	signer    *Signer
	rollover  *RolloverManager
	heartbeat *HeartbeatClient

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu              sync.RWMutex
	server          *http.Server
	tickerReset     chan time.Duration // signals the signing loop to reset its ticker
	signingLoopDead atomic.Bool        // true if signing loop goroutine has exited
	lastSigningRun  atomic.Int64       // unix timestamp of last signing loop iteration
}

// NewDaemon creates a new daemon instance
func NewDaemon(cfg *Config, state *State) *Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		cfg:         cfg,
		state:       state,
		signer:      NewSigner(cfg, state),
		rollover:    NewRolloverManager(cfg, state),
		heartbeat:   NewHeartbeatClient(&cfg.Heartbeat),
		ctx:         ctx,
		cancel:      cancel,
		tickerReset: make(chan time.Duration, 1),
	}
}

// Run starts the daemon's main loop
func (d *Daemon) Run() error {
	slog.Info("[DAEMON] starting")

	// Ensure directories exist
	if err := d.ensureDirectories(); err != nil {
		return err
	}

	// Validate startup requirements
	if err := d.validateStartup(); err != nil {
		return fmt.Errorf("startup validation failed: %w", err)
	}

	// Start heartbeat monitoring
	d.heartbeat.Start()

	// Start web server if enabled
	if d.cfg.Web.Enabled {
		d.wg.Add(1)
		go d.runWebServer()
	}

	// Start health server (always on a separate internal port if needed)
	d.wg.Add(1)
	go d.runHealthServer()

	// Main signing loop
	d.wg.Add(1)
	go d.runSigningLoop()

	// Wait for shutdown
	<-d.ctx.Done()
	d.wg.Wait()

	slog.Info("[DAEMON] stopped")
	return nil
}

// Shutdown gracefully stops the daemon
func (d *Daemon) Shutdown() {
	slog.Info("[DAEMON] Initiating graceful shutdown")

	// Stop heartbeat monitoring (sends stopping heartbeat)
	d.heartbeat.Stop()

	d.cancel()

	d.mu.Lock()
	shutdownTimeout := d.cfg.Health.ShutdownTimeout.Duration
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := d.server.Shutdown(ctx); err != nil {
			slog.Warn("[DAEMON] Error during server shutdown", "error", err)
		}
	}
	d.mu.Unlock()
}

// Reload updates the daemon's configuration and state
func (d *Daemon) Reload(cfg *Config, state *State) {
	d.mu.Lock()
	oldCfg := d.cfg

	// Stop old heartbeat client
	d.heartbeat.Stop()

	d.cfg = cfg
	d.state = state
	d.signer = NewSigner(cfg, state)
	d.rollover = NewRolloverManager(cfg, state)
	d.heartbeat = NewHeartbeatClient(&cfg.Heartbeat)

	// Start new heartbeat client
	d.heartbeat.Start()
	d.mu.Unlock()

	// Reset signing loop ticker if poll interval changed
	if cfg.PollInterval.Duration != oldCfg.PollInterval.Duration {
		select {
		case d.tickerReset <- cfg.PollInterval.Duration:
			slog.Info("[DAEMON] Poll interval updated", "old", oldCfg.PollInterval.String(), "new", cfg.PollInterval.String())
		default:
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

func (d *Daemon) ensureDirectories() error {
	// Data and output dirs need standard permissions
	for _, dir := range []string{d.cfg.DataDir, d.cfg.OutputDir} {
		if err := ensureDir(dir); err != nil {
			return err
		}
	}
	// Keys directory holds private keys — restrict to owner-only
	if err := ensureDirSecure(d.cfg.KeysDir()); err != nil {
		return err
	}
	return nil
}

// validateStartup performs startup checks to ensure the daemon can operate correctly
func (d *Daemon) validateStartup() error {
	// Verify output_dir is writable
	if err := d.checkDirWritable(d.cfg.OutputDir, "output_dir"); err != nil {
		return err
	}

	// Verify data_dir is writable
	if err := d.checkDirWritable(d.cfg.DataDir, "data_dir"); err != nil {
		return err
	}

	// Verify keys_dir is writable (with secure permissions)
	keysDir := d.cfg.KeysDir()
	if err := d.checkDirWritable(keysDir, "keys_dir"); err != nil {
		return err
	}

	// Verify state file is accessible
	if err := d.state.Save(); err != nil {
		return fmt.Errorf("cannot write state file: %w", err)
	}

	slog.Debug("[DAEMON] Startup validation passed")
	return nil
}

// checkDirWritable verifies a directory is writable
func (d *Daemon) checkDirWritable(dir, name string) error {
	testFile := filepath.Join(dir, ".startup_check")
	f, err := os.Create(testFile)
	if err != nil {
		return fmt.Errorf("%s not writable (%s): %w", name, dir, err)
	}
	f.Close()
	os.Remove(testFile)
	return nil
}

func (d *Daemon) runSigningLoop() {
	defer d.wg.Done()
	defer d.signingLoopDead.Store(true)

	ticker := time.NewTicker(d.cfg.PollInterval.Duration)
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
	cfg      *Config
	state    *State
	signer   *Signer
	rollover *RolloverManager
}

func (d *Daemon) takeSnapshot() snapshot {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return snapshot{
		cfg:      d.cfg,
		state:    d.state,
		signer:   d.signer,
		rollover: d.rollover,
	}
}

func (d *Daemon) signAllZones() {
	snap := d.takeSnapshot()

	// Record that the signing loop is alive
	d.lastSigningRun.Store(time.Now().Unix())

	// Reload state from disk to pick up any zones added by CLI commands
	if err := snap.state.ReloadFromDisk(); err != nil {
		slog.Warn("[DAEMON] Failed to reload state from disk", "error", err)
	}

	slog.Debug("[DAEMON] Checking zones for signing", "count", len(snap.cfg.Zones))

	// Track successfully-signed zones so we can fire one batched post-sign
	// hook at the end of the cycle when coalesce_post_sign is enabled.
	// With N=3000 zones, coalescing turns 3000 nsd-control reload calls
	// (one per zone) into exactly one, at the cost of losing the per-zone
	// DNSSEC_DOMAIN env var. Consumers get DNSSEC_DOMAINS (space-list) and
	// DNSSEC_BATCH_SIZE instead.
	var signedDomains []string
	for domain := range snap.cfg.Zones {
		if d.checkAndSignZoneSafe(snap, domain) {
			signedDomains = append(signedDomains, domain)
		}
	}

	// Check for automatic ZSK rollovers
	for domain := range snap.cfg.Zones {
		zoneState := snap.state.GetZone(domain)
		if zoneState == nil || zoneState.ZSK == nil {
			continue
		}
		if err := snap.rollover.CheckZSKRollover(domain); err != nil {
			slog.Error("[ROLLOVER] ZSK rollover check failed", "domain", domain, "error", err)
		}
	}

	// Save state
	if err := snap.state.Save(); err != nil {
		slog.Error("[DAEMON] Failed to save state", "error", err)
	}

	// Fire the coalesced post-sign hook after state is saved — this way
	// any consumer that introspects state.json sees the just-signed zones.
	if snap.cfg.Hooks.CoalescePostSign && len(signedDomains) > 0 {
		executeBatchHook(&snap.cfg.Hooks, signedDomains, snap.cfg.OutputDir)
	}

	// Update Prometheus metrics
	UpdateZoneMetrics(snap.state)
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

	// Send heartbeat for signing start
	d.heartbeat.SigningStart(domain)

	// Initialize zone state if new — but first try to recover existing key
	// files from disk. If key files already exist (e.g., state was lost but
	// keys survive), reuse them to preserve the DS chain of trust. Generating
	// new keys when a published DS still references the old key causes SERVFAIL.
	if zoneState == nil {
		keyGen := NewKeyGenerator(snap.cfg)
		ksk, zsk, err := recoverOrGenerateKeys(keyGen, domain)
		if err != nil {
			return false, err
		}
		zoneState = &ZoneState{
			Path: zoneCfg.Path,
			KSK:  ksk,
			ZSK:  zsk,
		}
		snap.state.SetZone(domain, zoneState)
	}

	// Sign the zone
	signStart := time.Now()
	if err := snap.signer.SignZone(domain); err != nil {
		snap.state.Mutate(func() { zoneState.AddError(err.Error()) })
		RecordSigningOperation(domain, time.Since(signStart).Seconds(), false)
		d.heartbeat.SigningError(domain)
		return false, err
	}

	// Clear errors on success and send completion heartbeat with the serial
	// actually served (differs from the unsigned serial under serial_policy
	// = "epoch")
	snap.state.Mutate(zoneState.ClearErrors)
	d.heartbeat.SigningComplete(domain, zoneState.PublishedSerial)

	// Execute per-zone post-sign hook only when NOT coalescing — the caller
	// will fire one batched hook at end-of-cycle when coalesce is on.
	if !snap.cfg.Hooks.CoalescePostSign {
		if snap.cfg.Hooks.PostSign != "" || len(snap.cfg.Hooks.PostSignCmd) > 0 {
			hookEnv := &HookEnv{
				Domain:     domain,
				ZonePath:   zoneCfg.Path,
				SignedPath: filepath.Join(snap.cfg.OutputDir, domain+".zone.signed"),
				OutputDir:  snap.cfg.OutputDir,
			}
			executeHook(&snap.cfg.Hooks, hookEnv)
		}
	}

	return true, nil
}

func (d *Daemon) runWebServer() {
	defer d.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[DAEMON] Panic in web server", "panic", r)
		}
	}()

	d.mu.Lock()
	d.server = NewWebServer(d.cfg, d.state)
	d.mu.Unlock()

	slog.Info("[WEB] Starting server", "listen", d.cfg.Web.Listen)

	if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("[WEB] Server error", "error", err)
	}
}

func (d *Daemon) runHealthServer() {
	defer d.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[DAEMON] Panic in health server", "panic", r)
		}
	}()

	d.mu.RLock()
	listenAddr := d.cfg.Health.Listen
	d.mu.RUnlock()

	// Health server runs on internal port for monitoring
	mux := http.NewServeMux()
	RegisterHealthHandlersWithDaemon(mux, d.state, d.cfg, d)
	mux.Handle("/metrics", promhttp.Handler())
	if d.cfg.Health.DebugVars {
		mux.Handle("/debug/vars", expvar.Handler())
		slog.Debug("[DAEMON] /debug/vars endpoint enabled")
	}

	server := &http.Server{
		Addr:              listenAddr,
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

	slog.Debug("[WEB] Starting health server", "listen", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("[WEB] Health server error", "error", err)
	}
}
