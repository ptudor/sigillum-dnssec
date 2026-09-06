package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
)

// heartbeatEventQueueSize bounds the async per-event heartbeat queue. When a
// blackholed endpoint stalls delivery, the oldest queued events are dropped so
// the signing loop never blocks and the most recent state still gets through.
const heartbeatEventQueueSize = 64

// HeartbeatClient sends periodic heartbeats to AnyStatus monitoring service
type HeartbeatClient struct {
	cfg *config.HeartbeatConfig

	mu         sync.RWMutex
	lastAction string
	lastSent   time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// events carries per-signing-event heartbeats (signing:*, rollover:*) to a
	// background worker so those sends are fire-and-forget and never block the
	// signing loop on the monitoring endpoint (R-044).
	events chan string

	httpClient *http.Client
}

// NewHeartbeatClient creates a new heartbeat client
func NewHeartbeatClient(cfg *config.HeartbeatConfig) *HeartbeatClient {
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
	resolvedCfg := *cfg
	resolvedCfg.InstanceID = instanceID

	return &HeartbeatClient{
		cfg:    &resolvedCfg,
		ctx:    ctx,
		cancel: cancel,
		events: make(chan string, heartbeatEventQueueSize),
		httpClient: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: heartbeatRedirectPolicy,
		},
	}
}

// heartbeatRedirectPolicy is the redirect policy for the credential-bearing
// heartbeat POST (RA6X-037). The API key travels in the form body, which a
// 307/308 replays to the redirect target, so a redirect may only stay on the
// configured origin (same scheme, host and port) and may never downgrade
// HTTPS to another scheme; the count is bounded. The explicit allow_insecure
// development override only permits an initial http:// URL — it does not
// relax the same-origin rule. Neither the key nor the URL is logged. This is
// the same policy the sibling validator's heartbeat client applies.
func heartbeatRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	orig := via[0].URL
	if orig.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing heartbeat redirect from %s to %s scheme (a downgrade would leak the api_key)", orig.Scheme, req.URL.Scheme)
	}
	if !strings.EqualFold(req.URL.Scheme, orig.Scheme) || !strings.EqualFold(req.URL.Host, orig.Host) {
		return fmt.Errorf("refusing cross-origin heartbeat redirect (the api_key must not be replayed to another origin)")
	}
	return nil
}

// enqueue queues a per-event heartbeat for asynchronous delivery so the signing
// loop never blocks on the monitoring endpoint. On backpressure (a slow or
// blackholed endpoint) it drops the OLDEST queued event to make room, so the
// newest state still gets through (R-044).
func (c *HeartbeatClient) enqueue(action string) {
	if !c.cfg.Enabled {
		return
	}
	select {
	case c.events <- action:
		return
	default:
	}
	// Queue full: drop the oldest, then enqueue the newest.
	select {
	case <-c.events:
	default:
	}
	select {
	case c.events <- action:
	default:
		slog.Debug("[HEARTBEAT] event queue full; dropping event", "action", action)
	}
}

// eventLoop delivers queued per-event heartbeats until the client is stopped.
func (c *HeartbeatClient) eventLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case action := <-c.events:
			if err := c.Send(action); err != nil {
				slog.Debug("[HEARTBEAT] async event send failed", "action", action, "error", err)
			}
		}
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

	req, err := http.NewRequest("POST", c.cfg.URL, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Tudor "+c.cfg.App+"/1.0 (AnyStatus heartbeat)")

	resp, err := c.httpClient.Do(req)
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

	// Start the background idle loop and the async per-event delivery worker.
	c.wg.Add(1)
	go c.backgroundLoop()
	c.wg.Add(1)
	go c.eventLoop()

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

// SigningStart sends a heartbeat indicating signing has started. Async
// (fire-and-forget) so it never blocks the signing loop (R-044).
func (c *HeartbeatClient) SigningStart(domain string) {
	c.enqueue(fmt.Sprintf("signing:start domain=%s", domain))
}

// SigningComplete sends a heartbeat indicating signing has completed (async).
func (c *HeartbeatClient) SigningComplete(domain string, serial uint32) {
	c.enqueue(fmt.Sprintf("signing:complete domain=%s serial=%d", domain, serial))
}

// SigningError sends a heartbeat indicating a signing error (async).
func (c *HeartbeatClient) SigningError(domain string) {
	c.enqueue(fmt.Sprintf("signing:error domain=%s", domain))
}

// RolloverStart sends a heartbeat indicating a rollover has started (async).
func (c *HeartbeatClient) RolloverStart(domain, rolloverType string) {
	c.enqueue(fmt.Sprintf("rollover:start domain=%s type=%s", domain, rolloverType))
}

// RolloverComplete sends a heartbeat indicating a rollover has completed (async).
func (c *HeartbeatClient) RolloverComplete(domain, rolloverType string) {
	c.enqueue(fmt.Sprintf("rollover:complete domain=%s type=%s", domain, rolloverType))
}

// LastStatus returns the last action sent and when it was sent
func (c *HeartbeatClient) LastStatus() (action string, sent time.Time) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastAction, c.lastSent
}
