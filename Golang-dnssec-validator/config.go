package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Default config file paths (checked in order)
var DefaultConfigPaths = []string{
	"/usr/local/etc/tudordns/dnssec-validator.toml",
	"/etc/tudordns/dnssec-validator.toml",
	"dnssec-validator.toml",
}

// Config holds all configuration for the application
type Config struct {
	// HTTP Server
	ListenAddr         string        `toml:"listen_addr"`
	ShutdownTimeoutSec int           `toml:"shutdown_timeout_seconds"`
	ShutdownTimeout    time.Duration `toml:"-"`

	// Root trust anchors
	RootAnchorsPath string `toml:"root_anchors_path"`
	RootAnchorsURL  string `toml:"root_anchors_url"`

	// DNS query settings
	QueryTimeoutSec          int    `toml:"query_timeout_seconds"`
	TotalTimeoutSec          int    `toml:"total_timeout_seconds"`
	MaxConcurrent            int    `toml:"max_concurrent"`             // max concurrent DNS queries within one validation
	MaxConcurrentValidations int    `toml:"max_concurrent_validations"` // global cap on in-flight validations (R-086)
	RecursiveResolver        string `toml:"recursive_resolver"`

	// RDAP settings
	RDAPBaseURL string `toml:"rdap_base_url"`

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

	// Trusted proxy CIDRs for honoring X-Forwarded-For / X-Real-IP.
	// Only requests coming from these CIDRs will have proxy headers trusted.
	TrustedProxyCIDRs []string `toml:"trusted_proxy_cidrs"`

	// Optional CIDR allowlist for /metrics endpoint.
	// Empty means no CIDR restriction.
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
		RootAnchorsPath:          "/etc/dnssec-validator/root-anchors.json",
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
		StaticDir: "./static",
		TrustedProxyCIDRs: []string{
			"127.0.0.0/8",
			"::1/128",
		},
		MetricsAllowedCIDRs: []string{},
		// Heartbeat defaults
		Heartbeat: HeartbeatConfig{
			Enabled:         false,
			URL:             "https://www.any53.com/any53/anystatus/heartbeat/",
			App:             "dnssec-validator",
			IntervalMinutes: 5,
		},
		HeartbeatEnabled:  false,
		HeartbeatURL:      "https://www.any53.com/any53/anystatus/heartbeat/",
		HeartbeatApp:      "dnssec-validator",
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
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	cfg.applyNestedToFlat()

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

	cfg.applyNestedToFlat()

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

// applyNestedToFlat copies nested struct values to flat fields for backwards compatibility.
func (c *Config) applyNestedToFlat() {
	// Convert seconds to durations
	c.ShutdownTimeout = time.Duration(c.ShutdownTimeoutSec) * time.Second
	c.QueryTimeout = time.Duration(c.QueryTimeoutSec) * time.Second
	c.TotalTimeout = time.Duration(c.TotalTimeoutSec) * time.Second

	// Rate limiting
	c.RateLimitPerSec = c.RateLimit.PerSec
	c.RateLimitBurst = c.RateLimit.Burst
	c.RateLimitCleanup = time.Duration(c.RateLimit.CleanupSec) * time.Second

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
	c.HeartbeatInterval = time.Duration(c.Heartbeat.IntervalMinutes) * time.Minute
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
	if c.RateLimit.CleanupSec <= 0 {
		return fmt.Errorf("rate_limit.cleanup_seconds must be positive")
	}

	// Validate timeouts
	if c.QueryTimeoutSec <= 0 {
		return fmt.Errorf("query_timeout_seconds must be positive")
	}
	if c.TotalTimeoutSec <= 0 {
		return fmt.Errorf("total_timeout_seconds must be positive")
	}
	if c.ShutdownTimeoutSec <= 0 {
		return fmt.Errorf("shutdown_timeout_seconds must be positive")
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

	// Validate heartbeat interval when enabled (time.NewTicker requires > 0)
	if c.Heartbeat.Enabled && c.Heartbeat.IntervalMinutes <= 0 {
		return fmt.Errorf("heartbeat.interval_minutes must be positive when heartbeat.enabled is true")
	}

	// The trust-anchor URL, when set, must be HTTPS — anchors fetched over
	// cleartext are MITM-able (defense-in-depth atop the live-root digest match). R-087.
	if c.RootAnchorsURL != "" && !strings.HasPrefix(strings.ToLower(c.RootAnchorsURL), "https://") {
		return fmt.Errorf("root_anchors_url must use https:// (got %q)", c.RootAnchorsURL)
	}

	return nil
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
		LogWarn("config", "ignoring malformed integer environment variable; using default",
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
