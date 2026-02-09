package main

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed static/*
var staticFiles embed.FS

// Server is the HTTP server for the DNSSEC validator
type Server struct {
	config        *Config
	anchorsStore  *AnchorsStore
	healthChecker *HealthChecker
	rateLimiter   *RateLimiter
	handlers      *Handlers
	mux           *http.ServeMux
	server        *http.Server
}

const nonSSEWriteTimeout = 30 * time.Second

// NewServer creates a new HTTP server
func NewServer(config *Config, anchorsStore *AnchorsStore) *Server {
	s := &Server{
		config:       config,
		anchorsStore: anchorsStore,
		mux:          http.NewServeMux(),
	}

	// Create components
	s.healthChecker = NewHealthChecker(anchorsStore)
	s.rateLimiter = NewRateLimiter(config.RateLimitPerSec, config.RateLimitBurst, config.RateLimitCleanup)
	s.handlers = NewHandlers(anchorsStore, config)

	// Register routes
	s.registerRoutes()

	return s
}

// registerRoutes sets up the HTTP routes
func (s *Server) registerRoutes() {
	// Health endpoints (no rate limiting)
	s.mux.Handle("/health", withWriteDeadline(nonSSEWriteTimeout, http.HandlerFunc(s.healthChecker.HealthHandler())))
	s.mux.Handle("/healthz", withWriteDeadline(nonSSEWriteTimeout, http.HandlerFunc(s.healthChecker.HealthzHandler())))

	// Metrics endpoint (no rate limiting)
	s.mux.Handle("/metrics", withWriteDeadline(nonSSEWriteTimeout, promhttp.Handler()))

	// API endpoints (with rate limiting)
	s.mux.Handle("/validate", s.rateLimiter.Middleware(http.HandlerFunc(s.handlers.HandleValidateSSE)))
	s.mux.Handle("/api/validate", withWriteDeadline(nonSSEWriteTimeout, s.rateLimiter.Middleware(http.HandlerFunc(s.handlers.HandleValidateJSON))))
	s.mux.Handle("/api/anchors", withWriteDeadline(nonSSEWriteTimeout, s.rateLimiter.Middleware(http.HandlerFunc(s.handlers.HandleAnchors))))

	// Static files for web UI
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		LogError("server", err, "action", "embed_static_files")
		return
	}

	// Read index.html for root path serving
	indexHTML, _ := fs.ReadFile(staticFS, "index.html")

	// Serve static files
	fileServer := http.FileServer(http.FS(staticFS))
	s.mux.Handle("/", withWriteDeadline(nonSSEWriteTimeout, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers for static files
		setSecurityHeaders(w)

		path := r.URL.Path
		LogDebug("static", "serving static file", "path", path, "method", r.Method)

		// Serve index.html for root path or /index.html (avoid FileServer redirects)
		if path == "/" || path == "" || path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexHTML)
			return
		}

		fileServer.ServeHTTP(w, r)
	})))
}

// withWriteDeadline applies a bounded response write deadline for non-SSE handlers.
// SSE routes are intentionally excluded because they are long-lived streams.
func withWriteDeadline(timeout time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if timeout > 0 {
			rc := http.NewResponseController(w)
			switch err := rc.SetWriteDeadline(time.Now().Add(timeout)); {
			case err == nil:
				defer rc.SetWriteDeadline(time.Time{})
			case errors.Is(err, http.ErrNotSupported):
				// Ignore unsupported writers (e.g., some tests/middleware wrappers).
			default:
				LogWarn("server", "failed to set write deadline", "path", r.URL.Path, "error", err.Error())
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Start starts the HTTP server
func (s *Server) Start() error {
	s.server = &http.Server{
		Addr:              s.config.ListenAddr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // Disabled: SSE connections are long-lived; per-request timeouts via context
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MiB
	}

	LogInfo("server", "starting HTTP server", "addr", s.config.ListenAddr)
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	LogInfo("server", "shutting down HTTP server")

	// Stop rate limiter cleanup goroutine
	if s.rateLimiter != nil {
		s.rateLimiter.Stop()
	}

	// Shutdown HTTP server
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}

	return nil
}
