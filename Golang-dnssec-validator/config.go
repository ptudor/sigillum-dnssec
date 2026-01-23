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
	QueryTimeout  time.Duration
	TotalTimeout  time.Duration
	MaxConcurrent int

	// Rate limiting
	RateLimitPerSec int
	RateLimitBurst  int
	RateLimitCleanup time.Duration

	// Logging
	LogFormat string
	LogLevel  string

	// Static files
	StaticDir string
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		ListenAddr:       ":8080",
		ShutdownTimeout:  30 * time.Second,
		RootAnchorsPath:  "/etc/dnssec-validator/root-anchors.json",
		RootAnchorsURL:   "https://internet.any53.com/dns/anchors/root-anchors.json",
		QueryTimeout:     5 * time.Second,
		TotalTimeout:     30 * time.Second,
		MaxConcurrent:    10,
		RateLimitPerSec:  10,
		RateLimitBurst:   30,
		RateLimitCleanup: 5 * time.Minute,
		LogFormat:        "json",
		LogLevel:         "info",
		StaticDir:        "./static",
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

	// Rate limiting
	cfg.RateLimitPerSec = getEnvInt("RATE_LIMIT_PER_SEC", cfg.RateLimitPerSec)
	cfg.RateLimitBurst = getEnvInt("RATE_LIMIT_BURST", cfg.RateLimitBurst)
	cfg.RateLimitCleanup = getEnvDuration("RATE_LIMIT_CLEANUP", cfg.RateLimitCleanup)

	// Logging
	cfg.LogFormat = getEnv("LOG_FORMAT", cfg.LogFormat)
	cfg.LogLevel = getEnv("LOG_LEVEL", cfg.LogLevel)

	// Static files
	cfg.StaticDir = getEnv("STATIC_DIR", cfg.StaticDir)

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

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val := os.Getenv(key); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}
