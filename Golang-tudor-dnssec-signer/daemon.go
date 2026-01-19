package main

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Daemon manages the signing loop and optional web server
type Daemon struct {
	cfg      *Config
	state    *State
	signer   *Signer
	rollover *RolloverManager

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.RWMutex
	server *http.Server
}

// NewDaemon creates a new daemon instance
func NewDaemon(cfg *Config, state *State) *Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		cfg:      cfg,
		state:    state,
		signer:   NewSigner(cfg, state),
		rollover: NewRolloverManager(cfg, state),
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Run starts the daemon's main loop
func (d *Daemon) Run() error {
	slog.Info("[DAEMON] starting")

	// Ensure directories exist
	if err := d.ensureDirectories(); err != nil {
		return err
	}

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
	d.cancel()

	d.mu.Lock()
	if d.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.server.Shutdown(ctx); err != nil {
			slog.Warn("[DAEMON] Error during server shutdown", "error", err)
		}
	}
	d.mu.Unlock()
}

// Reload updates the daemon's configuration
func (d *Daemon) Reload(cfg *Config) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.cfg = cfg
	d.signer = NewSigner(cfg, d.state)
	d.rollover = NewRolloverManager(cfg, d.state)

	slog.Info("[DAEMON] Configuration reloaded", "zones", len(cfg.Zones))
}

func (d *Daemon) ensureDirectories() error {
	dirs := []string{
		d.cfg.DataDir,
		d.cfg.KeysDir(),
		d.cfg.OutputDir,
	}

	for _, dir := range dirs {
		if err := ensureDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) runSigningLoop() {
	defer d.wg.Done()

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
		}
	}
}

func (d *Daemon) signAllZones() {
	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	slog.Debug("[DAEMON] Checking zones for signing", "count", len(cfg.Zones))

	for domain := range cfg.Zones {
		if err := d.checkAndSignZone(domain); err != nil {
			slog.Error("[DAEMON] Failed to sign zone", "domain", domain, "error", err)
		}
	}

	// Check for automatic ZSK rollovers
	d.checkZSKRollovers()

	// Save state
	if err := d.state.Save(); err != nil {
		slog.Error("[DAEMON] Failed to save state", "error", err)
	}
}

func (d *Daemon) checkAndSignZone(domain string) error {
	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	zoneState := d.state.GetZone(domain)

	// Check if zone needs signing
	zoneCfg := cfg.Zones[domain]
	needsSign, reason := d.signer.NeedsSign(domain, zoneCfg.Path, zoneState)
	if !needsSign {
		return nil
	}

	slog.Info("[DAEMON] Signing zone", "domain", domain, "reason", reason)

	// Initialize zone state if new
	if zoneState == nil {
		keyGen := NewKeyGenerator(cfg)
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
		d.state.SetZone(domain, zoneState)
	}

	// Sign the zone
	if err := d.signer.SignZone(domain); err != nil {
		zoneState.AddError(err.Error())
		return err
	}

	// Clear errors on success
	zoneState.ClearErrors()

	// Execute post-sign hook
	if cfg.Hooks.PostSign != "" {
		executeHook(cfg.Hooks.PostSign)
	}

	return nil
}

func (d *Daemon) checkZSKRollovers() {
	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	for domain := range cfg.Zones {
		zoneState := d.state.GetZone(domain)
		if zoneState == nil || zoneState.ZSK == nil {
			continue
		}

		// Check if ZSK needs rollover
		if err := d.rollover.CheckZSKRollover(domain); err != nil {
			slog.Error("[ROLLOVER] ZSK rollover check failed", "domain", domain, "error", err)
		}
	}
}

func (d *Daemon) runWebServer() {
	defer d.wg.Done()

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

	// Health server runs on internal port for monitoring
	mux := http.NewServeMux()
	RegisterHealthHandlers(mux, d.state)

	server := &http.Server{
		Addr:              "127.0.0.1:8054",
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
