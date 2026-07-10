package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ptudor/dnssec-validator/internal/heartbeat"
)

// Version and build information (set by ldflags)
var (
	Version   = "dev"
	BuildTime = "unknown"
)

func main() {
	// Load configuration
	config, err := LoadConfig()
	if err != nil {
		LogError("main", err, "action", "load_config")
		os.Exit(1)
	}

	// Setup logging
	if err := SetupLogging(config); err != nil {
		LogError("main", err, "action", "setup_logging")
		os.Exit(1)
	}
	defer CloseLogFile()

	// Log startup
	LogStartup(Version, BuildTime, config)

	// Create anchors store and load trust anchors
	anchorsStore := NewAnchorsStore(config.RootAnchorsPath, config.RootAnchorsURL)
	initialLoadErr := anchorsStore.Load()
	if initialLoadErr != nil {
		LogWarn("main", "failed to load root anchors at startup; will retry with backoff", "error", initialLoadErr.Error())
	} else {
		anchors := anchorsStore.Get()
		LogInfo("main", "loaded root trust anchors",
			"count", len(anchors.Anchors),
			"loaded_from", anchors.LoadedFrom,
			"data_source", anchors.Source,
		)
	}

	// Create and start server
	server := NewServer(config, anchorsStore)

	// Initialize heartbeat client
	hbClient := heartbeat.NewClient(heartbeat.Config{
		Enabled:    config.HeartbeatEnabled,
		URL:        config.HeartbeatURL,
		APIKey:     config.HeartbeatAPIKey,
		App:        config.HeartbeatApp,
		StatusURL:  config.HeartbeatStatusURL,
		InstanceID: config.HeartbeatInstanceID,
		Interval:   config.HeartbeatInterval,
	})

	// Start background heartbeat if enabled
	var cancelHeartbeat context.CancelFunc
	if hbClient.Enabled() {
		LogInfo("main", "heartbeat monitoring enabled",
			"app", config.HeartbeatApp,
			"interval", config.HeartbeatInterval.String(),
		)
		cancelHeartbeat = hbClient.StartBackground(context.Background(), config.HeartbeatInterval)
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Manage trust anchors in the background: recover from a failed startup load
	// via bounded backoff, then refresh on the 24h steady-state cadence.
	anchorDone := make(chan struct{})
	go func() {
		// If the initial load failed, retry with backoff until anchors are
		// available — independent of the 24h refresh — so a transient boot-time
		// failure doesn't leave every /validate returning 503 for up to a day
		// (R-089). Readiness is surfaced via /health's root_anchors check.
		if initialLoadErr != nil {
			backoff := 30 * time.Second
			const maxBackoff = 5 * time.Minute
			for {
				select {
				case <-anchorDone:
					return
				case <-time.After(backoff):
				}
				if err := anchorsStore.Load(); err != nil {
					LogWarn("main", "retry loading root anchors failed",
						"error", err.Error(), "next_retry_in", backoff.String())
					if backoff *= 2; backoff > maxBackoff {
						backoff = maxBackoff
					}
					continue
				}
				anchors := anchorsStore.Get()
				LogInfo("main", "loaded root trust anchors after retry",
					"count", len(anchors.Anchors), "loaded_from", anchors.LoadedFrom)
				SetRootAnchorsAge(anchorsStore.Age().Seconds())
				break
			}
		}

		// Steady-state refresh every 24 hours.
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := anchorsStore.Load(); err != nil {
					LogWarn("main", "failed to refresh root anchors", "error", err.Error())
				} else {
					LogInfo("main", "refreshed root trust anchors")
				}
				// Update metrics
				SetRootAnchorsAge(anchorsStore.Age().Seconds())
			case <-anchorDone:
				return
			}
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case sig := <-sigChan:
		LogShutdown(sig.String())

		// Stop anchor refresh goroutine
		close(anchorDone)

		// Stop heartbeat background sender (sends "stopping" action)
		if cancelHeartbeat != nil {
			cancelHeartbeat()
		}

		// Create shutdown context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout)
		defer cancel()

		// Shutdown server
		if err := server.Shutdown(ctx); err != nil {
			LogError("main", err, "action", "shutdown")
		}

	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			LogError("main", err, "action", "server_error")
			os.Exit(1)
		}
	}

	LogInfo("main", "server stopped")
}
