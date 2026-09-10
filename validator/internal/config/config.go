package config

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Default config file paths (checked in order)
var DefaultConfigPaths = []string{
	"/usr/local/etc/sigillum-validator/config.toml",
	"/etc/sigillum-validator/config.toml",
	"config.toml",
}

// Config holds all configuration for the application
type Config struct {
	// HTTP Server
	ListenAddr         string        `toml:"listen_addr"`
	ShutdownTimeoutSec int           `toml:"shutdown_timeout_seconds"`
	ShutdownTimeout    time.Duration `toml:"-"`

	// Root trust anchors. RootAnchorsCachePath is the last-known-good cache
	// (RDAYBLUEX-011): every usable, pinned document fetched from the URL is
	// persisted there atomically and read before the network on later
	// starts, so a restart during a mirror or network outage still validates.
	// It must be an absolute path in a directory writable by the service and
	// distinct from root_anchors_path; empty disables caching.
	RootAnchorsPath      string `toml:"root_anchors_path"`
	RootAnchorsCachePath string `toml:"root_anchors_cache_path"`
	RootAnchorsURL       string `toml:"root_anchors_url"`

	// DNS query settings
	QueryTimeoutSec          int    `toml:"query_timeout_seconds"`
	TotalTimeoutSec          int    `toml:"total_timeout_seconds"`
	MaxConcurrent            int    `toml:"max_concurrent"`             // max concurrent DNS queries within one validation
	MaxConcurrentValidations int    `toml:"max_concurrent_validations"` // global cap on in-flight validations (R-086)
	RecursiveResolver        string `toml:"recursive_resolver"`

	// RDAP settings. The base URL must be an absolute https:// URL without
	// userinfo, query or fragment (RDAYBLUEX-020); a plain http:// URL is
	// accepted only for a loopback host and only with the explicit
	// development override below (TOML-only, no environment fallback).
	RDAPBaseURL               string `toml:"rdap_base_url"`
	RDAPAllowInsecureLoopback bool   `toml:"rdap_allow_insecure_loopback"`

	// Parsed durations
	QueryTimeout time.Duration `toml:"-"`
	TotalTimeout time.Duration `toml:"-"`

	// Rate limiting
	RateLimit RateLimitConfig `toml:"rate_limit"`

	// Legacy flat fields (populated from nested structs after load)
	RateLimitPerSec  int           `toml:"-"`
	RateLimitBurst   int           `toml:"-"`
	RateLimitCleanup time.Duration `toml:"-"`

	// Logging
	Logging LoggingConfig `toml:"logging"`

	// Legacy flat fields
	LogFormat string `toml:"-"`
	LogLevel  string `toml:"-"`
	LogFile   string `toml:"-"`

	// Static files
	StaticDir string `toml:"static_dir"`

	// Base path (for reverse proxy, e.g., "/dnssec")
	BasePath string `toml:"base_path"`

	// Outbound DNS egress policy (RA6X-054). The addresses of authoritative
	// servers come from DNS data a client of the public service controls, so
	// by default only public unicast destinations are dialled: loopback,
	// link-local, private, CGNAT, multicast and reserved addresses are
	// refused (the configured recursive_resolver is always allowed).
	// private_destination_allowlist lists CIDRs that may be dialled anyway
	// (a private diagnostic deployment); allow_private_destinations = true
	// disables the check for a deliberately internal deployment.
	AllowPrivateDestinations    bool     `toml:"allow_private_destinations"`
	PrivateDestinationAllowlist []string `toml:"private_destination_allowlist"`

	// Trusted proxy CIDRs for honoring X-Forwarded-For / X-Real-IP.
	// Only requests coming from these CIDRs will have proxy headers trusted.
	TrustedProxyCIDRs []string `toml:"trusted_proxy_cidrs"`

	// CIDR allowlist for the /metrics endpoint. Defaults to loopback-only
	// (127.0.0.0/8, ::1/128) so metrics are not world-readable out of the box
	// (R-098). Set to the monitoring host/CIDR to scrape remotely, or to
	// ["0.0.0.0/0", "::/0"] to expose to everyone. An explicit empty list
	// removes all CIDR restriction.
	MetricsAllowedCIDRs []string `toml:"metrics_allowed_cidrs"`

	// Heartbeat monitoring (AnyStatus)
	Heartbeat HeartbeatConfig `toml:"heartbeat"`

	// Legacy flat fields for heartbeat
	HeartbeatEnabled    bool          `toml:"-"`
	HeartbeatURL        string        `toml:"-"`
	HeartbeatAPIKey     string        `toml:"-"`
	HeartbeatApp        string        `toml:"-"`
	HeartbeatStatusURL  string        `toml:"-"`
	HeartbeatInstanceID string        `toml:"-"`
	HeartbeatInterval   time.Duration `toml:"-"`
}

// RateLimitConfig holds rate limiting settings
type RateLimitConfig struct {
	PerSec     int `toml:"per_sec"`
	Burst      int `toml:"burst"`
	CleanupSec int `toml:"cleanup_seconds"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level  string `toml:"level"`
	Format string `toml:"format"`
	File   string `toml:"file"`
}

// HeartbeatConfig holds AnyStatus heartbeat configuration
type HeartbeatConfig struct {
	Enabled         bool   `toml:"enabled"`
	URL             string `toml:"url"`
	APIKey          string `toml:"api_key"`
	App             string `toml:"app"`
	StatusURL       string `toml:"status_url"`
	InstanceID      string `toml:"instance_id"`
	IntervalMinutes int    `toml:"interval_minutes"`
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:               ":8791",
		ShutdownTimeoutSec:       30,
		ShutdownTimeout:          30 * time.Second,
		RootAnchorsPath:          "/etc/sigillum-validator/root-anchors.json",
		RootAnchorsCachePath:     "/var/lib/sigillum-validator/root-anchors.json",
		RootAnchorsURL:           "https://internet.any53.com/dns/anchors/root-anchors.json",
		QueryTimeoutSec:          5,
		TotalTimeoutSec:          30,
		QueryTimeout:             5 * time.Second,
		TotalTimeout:             30 * time.Second,
		MaxConcurrent:            10,
		MaxConcurrentValidations: 100,
		RecursiveResolver:        "127.0.0.1",
		RDAPBaseURL:              "https://www.any53.com/rdap",
		RateLimit: RateLimitConfig{
			PerSec:     10,
			Burst:      30,
			CleanupSec: 300, // 5 minutes
		},
		RateLimitPerSec:  10,
		RateLimitBurst:   30,
		RateLimitCleanup: 5 * time.Minute,
		Logging: LoggingConfig{
			Format: "json",
			Level:  "info",
		},
		LogFormat: "json",
		LogLevel:  "info",
		// R-050: static_dir is a deprecated no-op — the server always serves the
		// embedded assets. Default to empty so a fresh config carries no value and
		// the startup deprecation warning fires only when an operator supplies one.
		StaticDir: "",
		TrustedProxyCIDRs: []string{
			"127.0.0.0/8",
			"::1/128",
		},
		// Secure by default: /metrics is loopback-only unless the operator
		// widens it (R-098). Prometheus metrics expose request/validation
		// internals, so they should not be world-readable out of the box. To
		// scrape from another host, set metrics_allowed_cidrs to the monitoring
		// host/CIDR; to intentionally expose them to everyone, set
		// ["0.0.0.0/0", "::/0"].
		MetricsAllowedCIDRs: []string{
			"127.0.0.0/8",
			"::1/128",
		},
		// Heartbeat defaults
		Heartbeat: HeartbeatConfig{
			Enabled:         false,
			URL:             "https://www.any53.com/any53/anystatus/heartbeat/",
			App:             "sigillum-validator",
			IntervalMinutes: 5,
		},
		HeartbeatEnabled:  false,
		HeartbeatURL:      "https://www.any53.com/any53/anystatus/heartbeat/",
		HeartbeatApp:      "sigillum-validator",
		HeartbeatInterval: 5 * time.Minute,
	}
}

// LoadFromFile loads configuration from a TOML file.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := DefaultConfig()
	// Strict decoding: reject unknown/misspelled keys instead of silently
	// ignoring them, so a typo like `max_concurent_validations` is a load-time
	// error rather than a silent revert to the default (R-093; same class as the
	// signer's R-015).
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		var strictErr *toml.StrictMissingError
		if errors.As(err, &strictErr) {
			return nil, fmt.Errorf("parsing config file: unknown key(s):\n%s", strictErr.String())
		}
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.applyNestedToFlat(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// Load loads configuration, trying TOML file first, then environment variables.
// If configPath is empty, it checks default paths for a TOML file.
func Load(configPath string) (*Config, error) {
	// If explicit path provided, use it
	if configPath != "" {
		return LoadFromFile(configPath)
	}

	// Check default TOML paths
	for _, path := range DefaultConfigPaths {
		if _, err := os.Stat(path); err == nil {
			return LoadFromFile(path)
		}
	}

	// Fall back to environment variables
	return LoadFromEnv()
}

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv() (*Config, error) {
	cfg := DefaultConfig()

	// HTTP Server
	cfg.ListenAddr = getEnv("LISTEN_ADDR", cfg.ListenAddr)
	cfg.ShutdownTimeoutSec = getEnvInt("SHUTDOWN_TIMEOUT_SECONDS", cfg.ShutdownTimeoutSec)

	// Root trust anchors
	cfg.RootAnchorsPath = getEnv("ROOT_ANCHORS_PATH", cfg.RootAnchorsPath)
	cfg.RootAnchorsCachePath = getEnv("ROOT_ANCHORS_CACHE_PATH", cfg.RootAnchorsCachePath)
	cfg.RootAnchorsURL = getEnv("ROOT_ANCHORS_URL", cfg.RootAnchorsURL)

	// DNS query settings
	cfg.QueryTimeoutSec = getEnvInt("QUERY_TIMEOUT_SECONDS", cfg.QueryTimeoutSec)
	cfg.TotalTimeoutSec = getEnvInt("TOTAL_TIMEOUT_SECONDS", cfg.TotalTimeoutSec)
	cfg.MaxConcurrent = getEnvInt("MAX_CONCURRENT", cfg.MaxConcurrent)
	cfg.MaxConcurrentValidations = getEnvInt("MAX_CONCURRENT_VALIDATIONS", cfg.MaxConcurrentValidations)
	cfg.RecursiveResolver = getEnv("RECURSIVE_RESOLVER", cfg.RecursiveResolver)

	// RDAP settings
	cfg.RDAPBaseURL = getEnv("RDAP_BASE_URL", cfg.RDAPBaseURL)

	// Rate limiting
	cfg.RateLimit.PerSec = getEnvInt("RATE_LIMIT_PER_SEC", cfg.RateLimit.PerSec)
	cfg.RateLimit.Burst = getEnvInt("RATE_LIMIT_BURST", cfg.RateLimit.Burst)
	cfg.RateLimit.CleanupSec = getEnvInt("RATE_LIMIT_CLEANUP_SECONDS", cfg.RateLimit.CleanupSec)

	// Logging
	cfg.Logging.Format = getEnv("LOG_FORMAT", cfg.Logging.Format)
	cfg.Logging.Level = getEnv("LOG_LEVEL", cfg.Logging.Level)
	cfg.Logging.File = getEnv("LOG_FILE", cfg.Logging.File)

	// Static files
	cfg.StaticDir = getEnv("STATIC_DIR", cfg.StaticDir)

	// Base path for reverse proxy
	cfg.BasePath = getEnv("BASE_PATH", cfg.BasePath)
	cfg.TrustedProxyCIDRs = getEnvCSV("TRUSTED_PROXY_CIDRS", cfg.TrustedProxyCIDRs)
	cfg.MetricsAllowedCIDRs = getEnvCSV("METRICS_ALLOWED_CIDRS", cfg.MetricsAllowedCIDRs)

	// Heartbeat monitoring (AnyStatus)
	cfg.Heartbeat.Enabled = getEnvBool("HEARTBEAT_ENABLED", cfg.Heartbeat.Enabled)
	cfg.Heartbeat.URL = getEnv("HEARTBEAT_URL", cfg.Heartbeat.URL)
	cfg.Heartbeat.APIKey = getEnv("HEARTBEAT_API_KEY", cfg.Heartbeat.APIKey)
	cfg.Heartbeat.App = getEnv("HEARTBEAT_APP", cfg.Heartbeat.App)
	cfg.Heartbeat.StatusURL = getEnv("HEARTBEAT_STATUS_URL", cfg.Heartbeat.StatusURL)
	cfg.Heartbeat.InstanceID = getEnv("HEARTBEAT_INSTANCE_ID", cfg.Heartbeat.InstanceID)
	cfg.Heartbeat.IntervalMinutes = getEnvInt("HEARTBEAT_INTERVAL_MINUTES", cfg.Heartbeat.IntervalMinutes)

	if err := cfg.applyNestedToFlat(); err != nil {
		return nil, err
	}

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadConfig loads configuration (backwards compatibility - uses Load with no path).
func LoadConfig() (*Config, error) {
	return Load("")
}

// Operational maxima for the integer duration settings (RDAYBLUEX-023). A
// technically representable multi-century timeout is never intended; each
// setting has a documented ceiling well below the point where the
// int→time.Duration multiplication could overflow.
const (
	MaxQueryTimeoutSec        = 300     // 5 minutes per server
	MaxTotalTimeoutSec        = 3600    // 1 hour per validation
	MaxShutdownTimeoutSec     = 600     // 10 minutes
	MaxRateLimitCleanupSec    = 86400   // 1 day
	MaxHeartbeatIntervalMinut = 24 * 60 // 1 day
)

// ValidateRootAnchorsCachePath checks the last-known-good anchor cache path
// (RDAYBLUEX-011): empty disables the cache; otherwise it must be absolute
// and must not name the operator's anchor file, which the service never
// writes.
func ValidateRootAnchorsCachePath(cachePath, anchorsPath string) error {
	cachePath = strings.TrimSpace(cachePath)
	if cachePath == "" {
		return nil
	}
	if !filepath.IsAbs(cachePath) {
		return fmt.Errorf("root_anchors_cache_path must be an absolute path (got %q)", cachePath)
	}
	if anchorsPath != "" && filepath.Clean(cachePath) == filepath.Clean(anchorsPath) {
		return fmt.Errorf("root_anchors_cache_path must differ from root_anchors_path (%q): the operator's anchor file is never written by the service", anchorsPath)
	}
	return nil
}

// checkedDuration converts an integer count of unit into a time.Duration,
// rejecting values that would overflow int64 nanoseconds, non-positive
// results, and values above the setting's operational maximum
// (RDAYBLUEX-023). The error names the field.
func checkedDuration(field string, n int, unit time.Duration, max int) (time.Duration, error) {
	if n <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %d", field, n)
	}
	if int64(n) > math.MaxInt64/int64(unit) {
		return 0, fmt.Errorf("%s = %d overflows the representable duration range", field, n)
	}
	if n > max {
		return 0, fmt.Errorf("%s = %d exceeds the maximum of %d", field, n, max)
	}
	d := time.Duration(n) * unit
	if d <= 0 {
		return 0, fmt.Errorf("%s = %d does not convert to a positive duration", field, n)
	}
	return d, nil
}

// applyNestedToFlat copies nested struct values to flat fields for backwards
// compatibility. Every integer-to-duration conversion is checked
// (RDAYBLUEX-023): an overflowing, non-positive or out-of-range value is a
// configuration error returned before any server, goroutine or ticker is
// built, never a wrapped duration that silently disables a bound or panics a
// ticker.
func (c *Config) applyNestedToFlat() error {
	var err error
	if c.ShutdownTimeout, err = checkedDuration("shutdown_timeout_seconds", c.ShutdownTimeoutSec, time.Second, MaxShutdownTimeoutSec); err != nil {
		return err
	}
	if c.QueryTimeout, err = checkedDuration("query_timeout_seconds", c.QueryTimeoutSec, time.Second, MaxQueryTimeoutSec); err != nil {
		return err
	}
	if c.TotalTimeout, err = checkedDuration("total_timeout_seconds", c.TotalTimeoutSec, time.Second, MaxTotalTimeoutSec); err != nil {
		return err
	}

	// Rate limiting
	c.RateLimitPerSec = c.RateLimit.PerSec
	c.RateLimitBurst = c.RateLimit.Burst
	if c.RateLimitCleanup, err = checkedDuration("rate_limit.cleanup_seconds", c.RateLimit.CleanupSec, time.Second, MaxRateLimitCleanupSec); err != nil {
		return err
	}

	// Logging
	c.LogFormat = c.Logging.Format
	c.LogLevel = c.Logging.Level
	c.LogFile = c.Logging.File

	// Heartbeat
	c.HeartbeatEnabled = c.Heartbeat.Enabled
	c.HeartbeatURL = c.Heartbeat.URL
	c.HeartbeatAPIKey = c.Heartbeat.APIKey
	c.HeartbeatApp = c.Heartbeat.App
	c.HeartbeatStatusURL = c.Heartbeat.StatusURL
	c.HeartbeatInstanceID = c.Heartbeat.InstanceID
	// The heartbeat interval only matters when the heartbeat is enabled; a
	// disabled heartbeat keeps a zero interval (Validate has always allowed
	// that) and never starts a ticker.
	if c.Heartbeat.Enabled {
		if c.HeartbeatInterval, err = checkedDuration("heartbeat.interval_minutes", c.Heartbeat.IntervalMinutes, time.Minute, MaxHeartbeatIntervalMinut); err != nil {
			return err
		}
	} else {
		c.HeartbeatInterval = 0
		if c.Heartbeat.IntervalMinutes > 0 && int64(c.Heartbeat.IntervalMinutes) <= math.MaxInt64/int64(time.Minute) {
			c.HeartbeatInterval = time.Duration(c.Heartbeat.IntervalMinutes) * time.Minute
		}
	}
	return nil
}

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	// Validate log level
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "warn", "error":
		// Valid
	default:
		return fmt.Errorf("invalid logging.level: %s (must be debug, info, warn, or error)", c.Logging.Level)
	}

	// Validate log format
	switch strings.ToLower(c.Logging.Format) {
	case "text", "json":
		// Valid
	default:
		return fmt.Errorf("invalid logging.format: %s (must be text or json)", c.Logging.Format)
	}

	// Validate rate limiting
	if c.RateLimit.PerSec <= 0 {
		return fmt.Errorf("rate_limit.per_sec must be positive")
	}
	if c.RateLimit.Burst <= 0 {
		return fmt.Errorf("rate_limit.burst must be positive")
	}

	// Every integer that becomes a duration is checked the same way the
	// loaders convert it (RDAYBLUEX-023): positive, within the representable
	// range and within its operational maximum. A derived duration that was
	// populated by some other path must agree with its integer.
	durations := []struct {
		field   string
		n       int
		unit    time.Duration
		max     int
		derived time.Duration
	}{
		{"rate_limit.cleanup_seconds", c.RateLimit.CleanupSec, time.Second, MaxRateLimitCleanupSec, c.RateLimitCleanup},
		{"query_timeout_seconds", c.QueryTimeoutSec, time.Second, MaxQueryTimeoutSec, c.QueryTimeout},
		{"total_timeout_seconds", c.TotalTimeoutSec, time.Second, MaxTotalTimeoutSec, c.TotalTimeout},
		{"shutdown_timeout_seconds", c.ShutdownTimeoutSec, time.Second, MaxShutdownTimeoutSec, c.ShutdownTimeout},
	}
	for _, d := range durations {
		want, err := checkedDuration(d.field, d.n, d.unit, d.max)
		if err != nil {
			return err
		}
		if d.derived != 0 && d.derived != want {
			return fmt.Errorf("%s = %d does not match its derived duration %s", d.field, d.n, d.derived)
		}
	}

	// Validate max concurrent
	if c.MaxConcurrent <= 0 {
		return fmt.Errorf("max_concurrent must be positive")
	}
	if c.MaxConcurrentValidations <= 0 {
		return fmt.Errorf("max_concurrent_validations must be positive")
	}

	// Validate base path
	if c.BasePath != "" {
		if c.BasePath == "/" {
			return fmt.Errorf("base_path must be empty or a path prefix like /dnssec, not /")
		}
		if !strings.HasPrefix(c.BasePath, "/") {
			return fmt.Errorf("base_path must start with '/'")
		}
		if strings.HasSuffix(c.BasePath, "/") {
			return fmt.Errorf("base_path must not have trailing slash")
		}
	}

	// Validate trusted proxy CIDRs
	for _, cidr := range c.TrustedProxyCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid trusted_proxy_cidrs entry %q: %w", cidr, err)
		}
	}

	// Validate the egress allowlist CIDRs
	for _, cidr := range c.PrivateDestinationAllowlist {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid private_destination_allowlist entry %q: %w", cidr, err)
		}
	}

	// Validate metrics allowlist CIDRs
	for _, cidr := range c.MetricsAllowedCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("invalid metrics_allowed_cidrs entry %q: %w", cidr, err)
		}
	}

	// Validate heartbeat interval when enabled (time.NewTicker requires > 0):
	// the same checked conversion as the loaders (RDAYBLUEX-023).
	if c.Heartbeat.Enabled {
		want, err := checkedDuration("heartbeat.interval_minutes", c.Heartbeat.IntervalMinutes, time.Minute, MaxHeartbeatIntervalMinut)
		if err != nil {
			return fmt.Errorf("%w (heartbeat.enabled is true)", err)
		}
		if c.HeartbeatInterval != 0 && c.HeartbeatInterval != want {
			return fmt.Errorf("heartbeat.interval_minutes = %d does not match its derived duration %s", c.Heartbeat.IntervalMinutes, c.HeartbeatInterval)
		}
	}

	// The last-known-good anchor cache (RDAYBLUEX-011) is written by the
	// service: absolute, and never the operator's own anchor file.
	if err := ValidateRootAnchorsCachePath(c.RootAnchorsCachePath, c.RootAnchorsPath); err != nil {
		return err
	}

	// The trust-anchor URL, when set, must be HTTPS — anchors fetched over
	// cleartext are MITM-able (defense-in-depth atop the live-root digest match). R-087.
	if c.RootAnchorsURL != "" && !strings.HasPrefix(strings.ToLower(c.RootAnchorsURL), "https://") {
		return fmt.Errorf("root_anchors_url must use https:// (got %q)", c.RootAnchorsURL)
	}

	// The RDAP base URL is a server-side egress target chosen by configuration
	// (RDAYBLUEX-020): absolute, HTTPS, no userinfo/query/fragment, no
	// ambiguous path. Cleartext is allowed only to a loopback host behind the
	// explicit development override.
	if err := ValidateRDAPBaseURL(c.RDAPBaseURL, c.RDAPAllowInsecureLoopback); err != nil {
		return err
	}

	// R-047: if heartbeat monitoring is enabled, fail startup on a misconfiguration
	// rather than silently disabling it (NewClient returns a disabled client for
	// missing key/app) or leaking the API key in cleartext. Require a nonempty API
	// key and app, and an HTTPS URL — the API key is sent in the POST body, so an
	// HTTP endpoint would transmit it in cleartext.
	if c.HeartbeatEnabled {
		if c.HeartbeatAPIKey == "" {
			return fmt.Errorf("heartbeat is enabled but heartbeat api_key is empty")
		}
		if c.HeartbeatApp == "" {
			return fmt.Errorf("heartbeat is enabled but heartbeat app is empty")
		}
		if c.HeartbeatURL == "" {
			return fmt.Errorf("heartbeat is enabled but heartbeat url is empty")
		}
		if !strings.HasPrefix(strings.ToLower(c.HeartbeatURL), "https://") {
			return fmt.Errorf("heartbeat url must use https:// (the api_key is sent in the request body); got %q", c.HeartbeatURL)
		}
	}

	return nil
}

// ValidateRDAPBaseURL checks an RDAP base URL (RDAYBLUEX-020). Empty means
// RDAP is disabled. Otherwise the URL must be absolute with an https scheme
// (or http only for a loopback literal/localhost host when
// allowInsecureLoopback is set), carry a host, and have no userinfo, query,
// fragment or ".." path segment.
func ValidateRDAPBaseURL(raw string, allowInsecureLoopback bool) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("rdap_base_url is not a valid URL: %w", err)
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("rdap_base_url must be an absolute URL with a host (got %q)", raw)
	}
	if u.User != nil {
		return fmt.Errorf("rdap_base_url must not carry userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" {
		return fmt.Errorf("rdap_base_url must not carry a query or fragment (got %q)", raw)
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == ".." || seg == "." {
			return fmt.Errorf("rdap_base_url path must not contain %q segments (got %q)", seg, raw)
		}
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		host := strings.ToLower(u.Hostname())
		ip := net.ParseIP(host)
		loopback := host == "localhost" || (ip != nil && ip.IsLoopback())
		if !allowInsecureLoopback {
			return fmt.Errorf("rdap_base_url must use https:// (got %q); a plain http:// URL is allowed only for a loopback host with rdap_allow_insecure_loopback = true", raw)
		}
		if !loopback {
			return fmt.Errorf("rdap_allow_insecure_loopback permits http:// only for a loopback literal or localhost, not %q", u.Hostname())
		}
		return nil
	default:
		return fmt.Errorf("rdap_base_url scheme must be https (got %q)", u.Scheme)
	}
}

// Helper functions for environment variable parsing

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
		// A present-but-unparseable value almost always means a misconfiguration
		// (e.g. "5s" where an integer is expected). Don't fall back silently.
		slog.Warn("[CONFIG] ignoring malformed integer environment variable; using default",
			"var", key, "value", val, "default", defaultVal)
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val := os.Getenv(key); val != "" {
		switch strings.ToLower(val) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return defaultVal
}

func getEnvCSV(key string, defaultVal []string) []string {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}

	parts := strings.Split(val, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
