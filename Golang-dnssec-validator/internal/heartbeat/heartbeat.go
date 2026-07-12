// Package heartbeat provides a client for the AnyStatus service monitoring system.
package heartbeat

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Client sends heartbeats to the AnyStatus monitoring service.
type Client struct {
	baseURL    string
	apiKey     string
	app        string
	statusURL  string
	instanceID string
	httpClient *http.Client
	enabled    bool

	mu         sync.Mutex
	lastAction string
	lastSent   time.Time

	// activeCount is the number of in-flight validations, maintained by request
	// handlers via ValidationStarted/ValidationFinished. The background ticker
	// reports "running" while it is nonzero (R-052).
	activeCount atomic.Int64
}

// ValidationStarted records that a validation began. Safe to call on a disabled
// client (it just increments the counter, which the disabled ticker never reads).
func (c *Client) ValidationStarted() { c.activeCount.Add(1) }

// ValidationFinished records that a validation completed.
func (c *Client) ValidationFinished() { c.activeCount.Add(-1) }

// periodicAction is the action the background ticker reports: "running" while any
// validation is in flight, "idle" otherwise (R-052).
func (c *Client) periodicAction() string {
	if c.activeCount.Load() > 0 {
		return "running"
	}
	return "idle"
}

// Config holds heartbeat configuration.
type Config struct {
	Enabled    bool
	URL        string
	APIKey     string
	App        string
	StatusURL  string
	InstanceID string
	Interval   time.Duration
}

// NewClient creates a new heartbeat client.
func NewClient(cfg Config) *Client {
	if !cfg.Enabled || cfg.APIKey == "" || cfg.App == "" {
		return &Client{enabled: false}
	}

	baseURL := cfg.URL
	if baseURL == "" {
		baseURL = "https://www.any53.com/any53/anystatus/heartbeat/"
	}

	instanceID := cfg.InstanceID
	if instanceID == "" {
		instanceID, _ = os.Hostname()
	}

	return &Client{
		baseURL:    baseURL,
		apiKey:     cfg.APIKey,
		app:        cfg.App,
		statusURL:  cfg.StatusURL,
		instanceID: instanceID,
		httpClient: &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: heartbeatRedirectPolicy,
		},
		enabled: true,
	}
}

// heartbeatRedirectPolicy refuses a redirect that would downgrade the scheme
// (HTTPS to anything else) or cross to a different origin (host:port). The API key
// travels in the POST body, so a 307/308 redirect to an HTTP or foreign host would
// leak it — validating only the configured URL is insufficient without this (R-047).
func heartbeatRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	orig := via[0].URL
	if orig.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing heartbeat redirect from %s to %s scheme (downgrade would leak api_key)", orig.Scheme, req.URL.Scheme)
	}
	if !strings.EqualFold(req.URL.Host, orig.Host) {
		return fmt.Errorf("refusing cross-origin heartbeat redirect from %q to %q", orig.Host, req.URL.Host)
	}
	return nil
}

// Send sends a heartbeat with the given action.
// Actions examples: "starting", "idle", "validating", "stopping"
func (c *Client) Send(action string) error {
	if !c.enabled {
		return nil
	}

	c.mu.Lock()
	c.lastAction = action
	c.lastSent = time.Now()
	c.mu.Unlock()

	params := url.Values{}
	params.Set("api_key", c.apiKey)
	params.Set("app", c.app)
	if action != "" {
		params.Set("action", action)
	}
	if c.statusURL != "" {
		params.Set("status_url", c.statusURL)
	}
	if c.instanceID != "" {
		params.Set("instance_id", c.instanceID)
	}

	req, err := http.NewRequest("POST", c.baseURL, strings.NewReader(params.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Tudor "+c.app+"/1.0 (AnyStatus heartbeat)")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		slog.Debug("Heartbeat send failed", "action", action, "error", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("heartbeat failed: HTTP %d", resp.StatusCode)
		slog.Debug("Heartbeat rejected", "action", action, "status", resp.StatusCode)
		return err
	}

	slog.Debug("Heartbeat sent", "action", action)
	return nil
}

// SendAsync sends a heartbeat without blocking.
func (c *Client) SendAsync(action string) {
	if !c.enabled {
		return
	}
	go func() {
		if err := c.Send(action); err != nil {
			// Log at debug level - heartbeat failures shouldn't spam logs
			slog.Debug("Async heartbeat failed", "action", action, "error", err)
		}
	}()
}

// Sendf sends a heartbeat with a formatted action string.
func (c *Client) Sendf(format string, args ...interface{}) error {
	return c.Send(fmt.Sprintf(format, args...))
}

// SendAsyncf sends an async heartbeat with a formatted action string.
func (c *Client) SendAsyncf(format string, args ...interface{}) {
	c.SendAsync(fmt.Sprintf(format, args...))
}

// StartBackground starts a background goroutine that sends periodic heartbeats.
// Returns a cancel function to stop the background heartbeats.
func (c *Client) StartBackground(ctx context.Context, interval time.Duration) context.CancelFunc {
	if !c.enabled {
		return func() {}
	}

	ctx, cancel := context.WithCancel(ctx)

	go func() {
		// Send initial heartbeat
		c.Send("starting")

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				c.Send("stopping")
				return
			case <-ticker.C:
				c.mu.Lock()
				lastAction := c.lastAction
				c.mu.Unlock()

				// R-052: report "running" while any validation is in flight,
				// "idle" otherwise, from the concurrency-safe active count that
				// request handlers maintain. Previously this checked for a
				// "validate:" lastAction prefix that no caller ever set, so the
				// heartbeat read idle even during long/concurrent validations.
				_ = lastAction
				c.Send(c.periodicAction())
			}
		}
	}()

	return cancel
}

// Status returns the last action and when it was sent.
func (c *Client) Status() (action string, sentAt time.Time, enabled bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastAction, c.lastSent, c.enabled
}

// Enabled returns whether the heartbeat client is enabled.
func (c *Client) Enabled() bool {
	return c.enabled
}
