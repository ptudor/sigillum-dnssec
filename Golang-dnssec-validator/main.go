package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
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

	// Log startup
	LogStartup(Version, BuildTime, config)

	// Create anchors store and load trust anchors
	anchorsStore := NewAnchorsStore(config.RootAnchorsPath, config.RootAnchorsURL)
	if err := anchorsStore.Load(); err != nil {
		LogWarn("main", "failed to load root anchors, will retry", "error", err.Error())
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

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Start()
	}()

	// Start periodic anchor refresh (every 24 hours)
	go func() {
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
			case <-sigChan:
				return
			}
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case sig := <-sigChan:
		LogShutdown(sig.String())

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
