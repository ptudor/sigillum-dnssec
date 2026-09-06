package main

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ptudor/sigillum-dnssec/validator/internal/config"
)

//go:embed static/*
var staticFiles embed.FS

// Server is the HTTP server for the DNSSEC validator
type Server struct {
	config        *config.Config
	anchorsStore  *AnchorsStore
	healthChecker *HealthChecker
	rateLimiter   *RateLimiter
	handlers      *Handlers
	mux           *http.ServeMux
	server        *http.Server
}

// nonSSEWriteTimeout is the socket write deadline armed at handler entry for
// non-SSE routes; a completed validation result re-arms its own delivery
// budget (RA6X-020). A variable so tests can shorten it.
var nonSSEWriteTimeout = 30 * time.Second

// NewServer creates a new HTTP server
func NewServer(config *config.Config, anchorsStore *AnchorsStore) *Server {
	s := &Server{
		config:       config,
		anchorsStore: anchorsStore,
		mux:          http.NewServeMux(),
	}

	if err := SetTrustedProxyCIDRs(config.TrustedProxyCIDRs); err != nil {
		LogWarn("server", "invalid trusted_proxy_cidrs, reverting to defaults", "error", err.Error())
		_ = SetTrustedProxyCIDRs(defaultTrustedProxyCIDRs)
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
	basePath := normalizeBasePath(s.config.BasePath)
	register := func(pattern string, handler http.Handler) {
		s.mux.Handle(pattern, handler)
		if basePath != "" {
			s.mux.Handle(joinWithBasePath(basePath, pattern), handler)
		}
	}

	// Health endpoints (no rate limiting)
	register("/health", withWriteDeadline(nonSSEWriteTimeout, http.HandlerFunc(s.healthChecker.HealthHandler())))
	register("/healthz", withWriteDeadline(nonSSEWriteTimeout, http.HandlerFunc(s.healthChecker.HealthzHandler())))

	// Metrics endpoint (no rate limiting)
	metricsHandler := noStoreHandler(promhttp.Handler())
	if len(s.config.MetricsAllowedCIDRs) > 0 {
		nets, err := parseCIDRs(s.config.MetricsAllowedCIDRs)
		if err != nil {
			// R-054: fail CLOSED. An invalid restriction must never expose /metrics
			// from any source IP — a defensive parse error must not silently become
			// a disclosure, even if a direct NewServer bypassed Config.Validate. Deny
			// rather than substitute defaults for the operator's invalid restriction.
			LogError("server", err, "action", "parse_metrics_cidrs",
				"effect", "metrics denied (invalid metrics_allowed_cidrs)")
			metricsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "metrics unavailable: invalid access restriction configured", http.StatusServiceUnavailable)
			})
		} else {
			metricsHandler = allowCIDRs(metricsHandler, nets)
		}
	}
	register("/metrics", withWriteDeadline(nonSSEWriteTimeout, metricsHandler))

	// API endpoints (with rate limiting)
	register("/validate", s.rateLimiter.Middleware(http.HandlerFunc(s.handlers.HandleValidateSSE)))
	register("/api/validate", withWriteDeadline(nonSSEWriteTimeout, s.rateLimiter.Middleware(http.HandlerFunc(s.handlers.HandleValidateJSON))))
	register("/api/anchors", withWriteDeadline(nonSSEWriteTimeout, s.rateLimiter.Middleware(http.HandlerFunc(s.handlers.HandleAnchors))))

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
	staticHandler := withWriteDeadline(nonSSEWriteTimeout, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers for static files
		setSecurityHeaders(w)

		path := r.URL.Path
		LogDebug("static", "serving static file", "path", path, "method", r.Method)

		// Serve index.html for root path or /index.html (avoid FileServer redirects)
		if path == "/" || path == "" || path == "/index.html" {
			setNoStore(w)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexHTML)
			return
		}

		// Static assets can be cached by clients and intermediaries.
		// Assets are bundled with the binary and refreshed on deployment.
		if isCacheableStaticAsset(path) {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=300")
		}

		fileServer.ServeHTTP(w, r)
	}))
	s.mux.Handle("/", staticHandler)

	if basePath != "" {
		stripBase := http.StripPrefix(basePath, staticHandler)
		s.mux.Handle(basePath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// R-048: redirect the exact base path to its slash form BEFORE serving
			// content. Serving the UI directly at "/dnssec" leaves the address bar
			// without a trailing slash, so browser-relative URLs (style.css, app.js,
			// validate, api/...) resolve against the parent and become root paths — a
			// reverse proxy exposing only "/dnssec/" then serves a page with no assets.
			// 308 preserves the request method; retain the query string.
			target := basePath + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
		}))
		s.mux.Handle(basePath+"/", stripBase)
	}
}

// SetActivityObserver wires an observer (e.g. the heartbeat client) that is
// notified on validation start/finish so periodic status reflects live request
// activity (R-052). Call once before Start.
func (s *Server) SetActivityObserver(o activityObserver) {
	s.handlers.SetActivityObserver(o)
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

func noStoreHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setNoStore(w)
		next.ServeHTTP(w, r)
	})
}

func normalizeBasePath(basePath string) string {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" || basePath == "/" {
		return ""
	}
	return strings.TrimSuffix(basePath, "/")
}

func joinWithBasePath(basePath, pattern string) string {
	if basePath == "" {
		return pattern
	}
	if pattern == "/" {
		return basePath + "/"
	}
	return basePath + pattern
}

func parseCIDRs(cidrs []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, err
		}
		nets = append(nets, network)
	}
	return nets, nil
}

func allowCIDRs(next http.Handler, cidrs []*net.IPNet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := net.ParseIP(extractClientIP(r))
		if clientIP == nil || !ipAllowed(clientIP, cidrs) {
			writeProblemDetails(w, ErrTypeForbidden, "Forbidden",
				http.StatusForbidden, "access to metrics endpoint is restricted", r.URL.Path)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ipAllowed(ip net.IP, cidrs []*net.IPNet) bool {
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func isCacheableStaticAsset(path string) bool {
	switch {
	case strings.HasSuffix(path, ".js"),
		strings.HasSuffix(path, ".css"),
		strings.HasSuffix(path, ".woff"),
		strings.HasSuffix(path, ".woff2"),
		strings.HasSuffix(path, ".ttf"),
		strings.HasSuffix(path, ".svg"),
		strings.HasSuffix(path, ".png"),
		strings.HasSuffix(path, ".jpg"),
		strings.HasSuffix(path, ".jpeg"),
		strings.HasSuffix(path, ".gif"),
		strings.HasSuffix(path, ".webp"),
		strings.HasSuffix(path, ".ico"):
		return true
	default:
		return false
	}
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
