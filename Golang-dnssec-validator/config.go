package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the application
type Config struct {
	// HTTP Server
	ListenAddr      string
	ShutdownTimeout time.Duration

	// Root trust anchors
	RootAnchorsPath string
	RootAnchorsURL  string

	// DNS query settings
	QueryTimeout      time.Duration
	TotalTimeout      time.Duration
	MaxConcurrent     int
	RecursiveResolver string // Recursive resolver for NS lookups (IP address)

	// Rate limiting
	RateLimitPerSec  int
	RateLimitBurst   int
	RateLimitCleanup time.Duration

	// Logging
	LogFormat string
	LogLevel  string
	LogFile   string // Path to log file (empty = stdout)

	// Static files
	StaticDir string

	// Base path (for reverse proxy, e.g., "/dnssec")
	BasePath string

	// Heartbeat monitoring (AnyStatus)
	HeartbeatEnabled    bool
	HeartbeatURL        string
	HeartbeatAPIKey     string
	HeartbeatApp        string
	HeartbeatStatusURL  string
	HeartbeatInstanceID string
	HeartbeatInterval   time.Duration
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:        ":8791",
		ShutdownTimeout:   30 * time.Second,
		RootAnchorsPath:   "/etc/dnssec-validator/root-anchors.json",
		RootAnchorsURL:    "https://internet.any53.com/dns/anchors/root-anchors.json",
		QueryTimeout:      5 * time.Second,
		TotalTimeout:      30 * time.Second,
		MaxConcurrent:     10,
		RecursiveResolver: "8.8.8.8",
		RateLimitPerSec:   10,
		RateLimitBurst:    30,
		RateLimitCleanup:  5 * time.Minute,
		LogFormat:         "json",
		LogLevel:          "info",
		StaticDir:         "./static",
		// Heartbeat defaults
		HeartbeatEnabled:  false,
		HeartbeatURL:      "https://www.any53.com/any53/anystatus/heartbeat/",
		HeartbeatApp:      "dnssec-validator",
		HeartbeatInterval: 5 * time.Minute,
	}
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	cfg := DefaultConfig()

	// HTTP Server
	cfg.ListenAddr = getEnv("LISTEN_ADDR", cfg.ListenAddr)
	cfg.ShutdownTimeout = time.Duration(getEnvInt("SHUTDOWN_TIMEOUT_SECONDS", 30)) * time.Second

	// Root trust anchors
	cfg.RootAnchorsPath = getEnv("ROOT_ANCHORS_PATH", cfg.RootAnchorsPath)
	cfg.RootAnchorsURL = getEnv("ROOT_ANCHORS_URL", cfg.RootAnchorsURL)

	// DNS query settings
	cfg.QueryTimeout = getEnvDuration("QUERY_TIMEOUT", cfg.QueryTimeout)
	cfg.TotalTimeout = getEnvDuration("TOTAL_TIMEOUT", cfg.TotalTimeout)
	cfg.MaxConcurrent = getEnvInt("MAX_CONCURRENT", cfg.MaxConcurrent)
	cfg.RecursiveResolver = getEnv("RECURSIVE_RESOLVER", cfg.RecursiveResolver)

	// Rate limiting
	cfg.RateLimitPerSec = getEnvInt("RATE_LIMIT_PER_SEC", cfg.RateLimitPerSec)
	cfg.RateLimitBurst = getEnvInt("RATE_LIMIT_BURST", cfg.RateLimitBurst)
	cfg.RateLimitCleanup = getEnvDuration("RATE_LIMIT_CLEANUP", cfg.RateLimitCleanup)

	// Logging
	cfg.LogFormat = getEnv("LOG_FORMAT", cfg.LogFormat)
	cfg.LogLevel = getEnv("LOG_LEVEL", cfg.LogLevel)
	cfg.LogFile = getEnv("LOG_FILE", cfg.LogFile)

	// Static files
	cfg.StaticDir = getEnv("STATIC_DIR", cfg.StaticDir)

	// Base path for reverse proxy
	cfg.BasePath = getEnv("BASE_PATH", cfg.BasePath)

	// Heartbeat monitoring (AnyStatus)
	cfg.HeartbeatEnabled = getEnvBool("HEARTBEAT_ENABLED", cfg.HeartbeatEnabled)
	cfg.HeartbeatURL = getEnv("HEARTBEAT_URL", cfg.HeartbeatURL)
	cfg.HeartbeatAPIKey = getEnv("HEARTBEAT_API_KEY", cfg.HeartbeatAPIKey)
	cfg.HeartbeatApp = getEnv("HEARTBEAT_APP", cfg.HeartbeatApp)
	cfg.HeartbeatStatusURL = getEnv("HEARTBEAT_STATUS_URL", cfg.HeartbeatStatusURL)
	cfg.HeartbeatInstanceID = getEnv("HEARTBEAT_INSTANCE_ID", cfg.HeartbeatInstanceID)
	cfg.HeartbeatInterval = getEnvDuration("HEARTBEAT_INTERVAL", cfg.HeartbeatInterval)

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	// Validate log level
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
		// Valid
	default:
		return fmt.Errorf("invalid LOG_LEVEL: %s (must be debug, info, warn, or error)", c.LogLevel)
	}

	// Validate log format
	switch strings.ToLower(c.LogFormat) {
	case "text", "json":
		// Valid
	default:
		return fmt.Errorf("invalid LOG_FORMAT: %s (must be text or json)", c.LogFormat)
	}

	// Validate rate limiting
	if c.RateLimitPerSec <= 0 {
		return fmt.Errorf("RATE_LIMIT_PER_SEC must be positive")
	}
	if c.RateLimitBurst <= 0 {
		return fmt.Errorf("RATE_LIMIT_BURST must be positive")
	}

	// Validate timeouts
	if c.QueryTimeout <= 0 {
		return fmt.Errorf("QUERY_TIMEOUT must be positive")
	}
	if c.TotalTimeout <= 0 {
		return fmt.Errorf("TOTAL_TIMEOUT must be positive")
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("SHUTDOWN_TIMEOUT_SECONDS must be positive")
	}

	// Validate max concurrent
	if c.MaxConcurrent <= 0 {
		return fmt.Errorf("MAX_CONCURRENT must be positive")
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

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}
