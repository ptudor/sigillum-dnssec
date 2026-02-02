package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// HeartbeatClient sends periodic heartbeats to AnyStatus monitoring service
type HeartbeatClient struct {
	cfg *HeartbeatConfig

	mu         sync.RWMutex
	lastAction string
	lastSent   time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	httpClient *http.Client
}

// NewHeartbeatClient creates a new heartbeat client
func NewHeartbeatClient(cfg *HeartbeatConfig) *HeartbeatClient {
	ctx, cancel := context.WithCancel(context.Background())

	// Set instance_id to hostname if not specified
	instanceID := cfg.InstanceID
	if instanceID == "" {
		hostname, err := os.Hostname()
		if err == nil {
			instanceID = hostname
		}
	}

	// Create a copy of config with resolved instance_id
	resolvedCfg := &HeartbeatConfig{
		Enabled:         cfg.Enabled,
		URL:             cfg.URL,
		APIKey:          cfg.APIKey,
		App:             cfg.App,
		StatusURL:       cfg.StatusURL,
		InstanceID:      instanceID,
		IntervalMinutes: cfg.IntervalMinutes,
	}

	return &HeartbeatClient{
		cfg:    resolvedCfg,
		ctx:    ctx,
		cancel: cancel,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Send sends a heartbeat with the given action
func (c *HeartbeatClient) Send(action string) error {
	if !c.cfg.Enabled {
		return nil
	}

	params := url.Values{}
	params.Set("api_key", c.cfg.APIKey)
	params.Set("app", c.cfg.App)
	if action != "" {
		params.Set("action", action)
	}
	if c.cfg.StatusURL != "" {
		params.Set("status_url", c.cfg.StatusURL)
	}
	if c.cfg.InstanceID != "" {
		params.Set("instance_id", c.cfg.InstanceID)
	}

	resp, err := c.httpClient.PostForm(c.cfg.URL, params)
	if err != nil {
		slog.Debug("[HEARTBEAT] Failed to send", "action", action, "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("heartbeat failed: HTTP %d", resp.StatusCode)
		slog.Debug("[HEARTBEAT] Failed to send", "action", action, "status", resp.StatusCode)
		return err
	}

	c.mu.Lock()
	c.lastAction = action
	c.lastSent = time.Now()
	c.mu.Unlock()

	slog.Debug("[HEARTBEAT] Sent", "action", action)
	return nil
}

// Start begins background heartbeat sending
func (c *HeartbeatClient) Start() {
	if !c.cfg.Enabled {
		slog.Debug("[HEARTBEAT] Disabled, skipping background heartbeat")
		return
	}

	// Send starting heartbeat immediately
	if err := c.Send("starting"); err != nil {
		slog.Warn("[HEARTBEAT] Failed to send starting heartbeat", "error", err)
	}

	// Start background goroutine
	c.wg.Add(1)
	go c.backgroundLoop()

	slog.Info("[HEARTBEAT] Started background heartbeat",
		"interval_minutes", c.cfg.IntervalMinutes,
		"app", c.cfg.App,
		"instance_id", c.cfg.InstanceID)
}

// Stop stops background heartbeat sending and sends a stopping heartbeat
func (c *HeartbeatClient) Stop() {
	if !c.cfg.Enabled {
		return
	}

	// Send stopping heartbeat
	if err := c.Send("stopping"); err != nil {
		slog.Debug("[HEARTBEAT] Failed to send stopping heartbeat", "error", err)
	}

	c.cancel()
	c.wg.Wait()
	slog.Debug("[HEARTBEAT] Stopped")
}

// backgroundLoop sends periodic idle heartbeats
func (c *HeartbeatClient) backgroundLoop() {
	defer c.wg.Done()

	interval := time.Duration(c.cfg.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if err := c.Send("idle"); err != nil {
				slog.Debug("[HEARTBEAT] Background heartbeat failed", "error", err)
			}
		}
	}
}

// SigningStart sends a heartbeat indicating signing has started
func (c *HeartbeatClient) SigningStart(domain string) {
	if c.cfg.Enabled {
		c.Send(fmt.Sprintf("signing:start domain=%s", domain))
	}
}

// SigningComplete sends a heartbeat indicating signing has completed
func (c *HeartbeatClient) SigningComplete(domain string, serial uint32) {
	if c.cfg.Enabled {
		c.Send(fmt.Sprintf("signing:complete domain=%s serial=%d", domain, serial))
	}
}

// SigningError sends a heartbeat indicating a signing error
func (c *HeartbeatClient) SigningError(domain string) {
	if c.cfg.Enabled {
		c.Send(fmt.Sprintf("signing:error domain=%s", domain))
	}
}

// RolloverStart sends a heartbeat indicating a rollover has started
func (c *HeartbeatClient) RolloverStart(domain, rolloverType string) {
	if c.cfg.Enabled {
		c.Send(fmt.Sprintf("rollover:start domain=%s type=%s", domain, rolloverType))
	}
}

// RolloverComplete sends a heartbeat indicating a rollover has completed
func (c *HeartbeatClient) RolloverComplete(domain, rolloverType string) {
	if c.cfg.Enabled {
		c.Send(fmt.Sprintf("rollover:complete domain=%s type=%s", domain, rolloverType))
	}
}

// LastStatus returns the last action sent and when it was sent
func (c *HeartbeatClient) LastStatus() (action string, sent time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastAction, c.lastSent
}
