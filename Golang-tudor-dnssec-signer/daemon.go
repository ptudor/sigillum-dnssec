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

	mu          sync.RWMutex
	server      *http.Server
	tickerReset chan time.Duration // signals the signing loop to reset its ticker
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
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[DAEMON] Panic in signing loop", "panic", r)
		}
	}()

	ticker := time.NewTicker(d.cfg.PollInterval.Duration)
	defer ticker.Stop()

	// Initial sign
	d.signAllZones()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.signAllZones()
		case newInterval := <-d.tickerReset:
			ticker.Reset(newInterval)
		}
	}
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

	// Reload state from disk to pick up any zones added by CLI commands
	if err := snap.state.ReloadFromDisk(); err != nil {
		slog.Warn("[DAEMON] Failed to reload state from disk", "error", err)
	}

	slog.Debug("[DAEMON] Checking zones for signing", "count", len(snap.cfg.Zones))

	for domain := range snap.cfg.Zones {
		if err := d.checkAndSignZone(snap, domain); err != nil {
			slog.Error("[DAEMON] Failed to sign zone", "domain", domain, "error", err)
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

	// Update Prometheus metrics
	UpdateZoneMetrics(snap.state)
}

func (d *Daemon) checkAndSignZone(snap snapshot, domain string) error {
	zoneState := snap.state.GetZone(domain)

	// Check if zone needs signing
	zoneCfg := snap.cfg.Zones[domain]
	needsSign, reason := snap.signer.NeedsSign(domain, zoneCfg.Path, zoneState)
	if !needsSign {
		slog.Debug("[DAEMON] Zone does not need signing", "domain", domain, "path", zoneCfg.Path)
		return nil
	}

	slog.Info("[DAEMON] Signing zone", "domain", domain, "reason", reason)

	// Send heartbeat for signing start
	d.heartbeat.SigningStart(domain)

	// Initialize zone state if new
	if zoneState == nil {
		keyGen := NewKeyGenerator(snap.cfg)
		ksk, err := keyGen.GenerateKSK(domain)
		if err != nil {
			return err
		}
		zsk, err := keyGen.GenerateZSK(domain)
		if err != nil {
			return err
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
		zoneState.AddError(err.Error())
		RecordSigningOperation(domain, time.Since(signStart).Seconds(), false)
		d.heartbeat.SigningError(domain)
		return err
	}

	// Clear errors on success and send completion heartbeat
	zoneState.ClearErrors()
	d.heartbeat.SigningComplete(domain, zoneState.Serial)

	// Execute post-sign hook
	if snap.cfg.Hooks.PostSign != "" || len(snap.cfg.Hooks.PostSignCmd) > 0 {
		hookEnv := &HookEnv{
			Domain:     domain,
			ZonePath:   zoneCfg.Path,
			SignedPath: filepath.Join(snap.cfg.OutputDir, domain+".zone.signed"),
			OutputDir:  snap.cfg.OutputDir,
		}
		executeHook(&snap.cfg.Hooks, hookEnv)
	}

	return nil
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
	RegisterHealthHandlers(mux, d.state, d.cfg)
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
