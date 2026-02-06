package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config represents the main configuration structure
type Config struct {
	OutputDir    string                `toml:"output_dir"`
	DataDir      string                `toml:"data_dir"`
	PollInterval Duration              `toml:"poll_interval"`
	DNSSEC       DNSSECConfig          `toml:"dnssec"`
	Web          WebConfig             `toml:"web"`
	Health       HealthConfig          `toml:"health"`
	Heartbeat    HeartbeatConfig       `toml:"heartbeat"`
	Zones        map[string]ZoneConfig `toml:"zones"`
	Hooks        HooksConfig           `toml:"hooks"`
}

// HeartbeatConfig holds AnyStatus heartbeat monitoring settings
type HeartbeatConfig struct {
	Enabled         bool   `toml:"enabled"`
	URL             string `toml:"url"`
	APIKey          string `toml:"api_key"`
	App             string `toml:"app"`
	StatusURL       string `toml:"status_url"`
	InstanceID      string `toml:"instance_id"`
	IntervalMinutes int    `toml:"interval_minutes"`
}

// DNSSECConfig holds DNSSEC-specific settings
type DNSSECConfig struct {
	Algorithm          string   `toml:"algorithm"`
	KSKLifetime        Duration `toml:"ksk_lifetime"`
	ZSKLifetime        Duration `toml:"zsk_lifetime"`
	SignatureValidity  Duration `toml:"signature_validity"`
	SignatureRefresh   Duration `toml:"signature_refresh"`
	NSECVersion        string   `toml:"nsec_version"`
	NSEC3Iterations    int      `toml:"nsec3_iterations"`
	NSEC3Salt          string   `toml:"nsec3_salt"`
	DNSKEYTtl          uint32   `toml:"dnskey_ttl"`          // TTL for DNSKEY records (0 = use SOA TTL)
	RolloverPrepublish Duration `toml:"rollover_prepublish"` // Time before expiry to prepublish new key
	RolloverSwitch     Duration `toml:"rollover_switch"`     // Time to wait before switching to new key
}

// WebConfig holds web UI settings
type WebConfig struct {
	Enabled bool   `toml:"enabled"`
	Listen  string `toml:"listen"`
}

// HealthConfig holds health server settings
type HealthConfig struct {
	Listen          string   `toml:"listen"`
	ShutdownTimeout Duration `toml:"shutdown_timeout"`
}

// ZoneConfig holds per-zone settings
type ZoneConfig struct {
	Path        string   `toml:"path"`
	KSKLifetime Duration `toml:"ksk_lifetime,omitempty"`
	ZSKLifetime Duration `toml:"zsk_lifetime,omitempty"`
	Algorithm   string   `toml:"algorithm,omitempty"` // Per-zone algorithm override for algorithm rollover
}

// HooksConfig holds hook settings
type HooksConfig struct {
	PostSign string `toml:"post_sign"`
}

// Duration wraps time.Duration for TOML parsing
type Duration struct {
	time.Duration
}

// UnmarshalText implements encoding.TextUnmarshaler for Duration
func (d *Duration) UnmarshalText(text []byte) error {
	s := string(text)

	// Handle year/month suffixes not supported by time.ParseDuration
	if len(s) > 0 {
		suffix := s[len(s)-1]
		switch suffix {
		case 'y', 'Y':
			// Parse years (approximate: 365 days)
			var years float64
			if _, err := fmt.Sscanf(s[:len(s)-1], "%f", &years); err == nil {
				d.Duration = time.Duration(years * 365 * 24 * float64(time.Hour))
				return nil
			}
		case 'M':
			// Parse months (approximate: 30 days)
			var months float64
			if _, err := fmt.Sscanf(s[:len(s)-1], "%f", &months); err == nil {
				d.Duration = time.Duration(months * 30 * 24 * float64(time.Hour))
				return nil
			}
		case 'd', 'D':
			// Parse days
			var days float64
			if _, err := fmt.Sscanf(s[:len(s)-1], "%f", &days); err == nil {
				d.Duration = time.Duration(days * 24 * float64(time.Hour))
				return nil
			}
		}
	}

	// Fall back to standard duration parsing
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// MarshalText implements encoding.TextMarshaler for Duration
func (d Duration) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// String returns a human-readable duration string
func (d Duration) String() string {
	if d.Duration == 0 {
		return "0s"
	}

	hours := d.Duration.Hours()
	if hours >= 8760 { // ~365 days
		years := hours / 8760
		if years == float64(int(years)) {
			return fmt.Sprintf("%dy", int(years))
		}
		return fmt.Sprintf("%.1fy", years)
	}
	if hours >= 24 {
		days := hours / 24
		if days == float64(int(days)) {
			return fmt.Sprintf("%dd", int(days))
		}
		return fmt.Sprintf("%.1fd", days)
	}
	return d.Duration.String()
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		OutputDir:    "/var/lib/dnssec-tudor/signed",
		DataDir:      "/var/lib/dnssec-tudor",
		PollInterval: Duration{5 * time.Minute},
		DNSSEC: DNSSECConfig{
			Algorithm:          "ED25519",
			KSKLifetime:        Duration{3 * 365 * 24 * time.Hour}, // 3 years
			ZSKLifetime:        Duration{90 * 24 * time.Hour},      // 90 days
			SignatureValidity:  Duration{14 * 24 * time.Hour},      // 14 days
			SignatureRefresh:   Duration{3 * 24 * time.Hour},       // 3 days
			NSECVersion:        "nsec3",
			NSEC3Iterations:    0,
			NSEC3Salt:          "",
			DNSKEYTtl:          0,                             // 0 = use SOA TTL
			RolloverPrepublish: Duration{14 * 24 * time.Hour}, // 14 days before expiry
			RolloverSwitch:     Duration{7 * 24 * time.Hour},  // 7 days to switch signing
		},
		Web: WebConfig{
			Enabled: false,
			Listen:  "127.0.0.1:8053",
		},
		Health: HealthConfig{
			Listen:          "127.0.0.1:8054",
			ShutdownTimeout: Duration{30 * time.Second},
		},
		Heartbeat: HeartbeatConfig{
			Enabled:         false,
			URL:             "https://www.any53.com/any53/anystatus/heartbeat/",
			App:             "dnssec-tudor",
			IntervalMinutes: 5,
		},
		Zones: make(map[string]ZoneConfig),
		Hooks: HooksConfig{},
	}
}

// LoadConfig loads configuration from a TOML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	// Validate algorithm
	validAlgorithms := map[string]bool{
		"ED25519":         true,
		"ECDSAP256SHA256": true,
		"ECDSAP384SHA384": true,
	}
	if !validAlgorithms[c.DNSSEC.Algorithm] {
		return fmt.Errorf("unsupported algorithm %q (supported: ED25519, ECDSAP256SHA256, ECDSAP384SHA384)", c.DNSSEC.Algorithm)
	}

	// Validate per-zone algorithms
	for domain, zone := range c.Zones {
		if zone.Algorithm != "" && !validAlgorithms[zone.Algorithm] {
			return fmt.Errorf("zone %q has unsupported algorithm %q", domain, zone.Algorithm)
		}
	}

	// Validate NSEC version
	if c.DNSSEC.NSECVersion != "nsec" && c.DNSSEC.NSECVersion != "nsec3" {
		return fmt.Errorf("nsec_version must be 'nsec' or 'nsec3', got %q", c.DNSSEC.NSECVersion)
	}

	// Validate durations are positive
	if c.DNSSEC.KSKLifetime.Duration <= 0 {
		return fmt.Errorf("ksk_lifetime must be positive")
	}
	if c.DNSSEC.ZSKLifetime.Duration <= 0 {
		return fmt.Errorf("zsk_lifetime must be positive")
	}
	if c.DNSSEC.SignatureValidity.Duration <= 0 {
		return fmt.Errorf("signature_validity must be positive")
	}
	if c.DNSSEC.SignatureRefresh.Duration <= 0 {
		return fmt.Errorf("signature_refresh must be positive")
	}

	// Validate signature_refresh < signature_validity
	if c.DNSSEC.SignatureRefresh.Duration >= c.DNSSEC.SignatureValidity.Duration {
		return fmt.Errorf("signature_refresh (%s) must be less than signature_validity (%s)",
			c.DNSSEC.SignatureRefresh.String(), c.DNSSEC.SignatureValidity.String())
	}

	// Validate NSEC3 iterations (RFC 9276 recommends 0)
	if c.DNSSEC.NSEC3Iterations < 0 || c.DNSSEC.NSEC3Iterations > 150 {
		return fmt.Errorf("nsec3_iterations must be between 0 and 150")
	}

	// Validate NSEC3 salt is valid hex if provided
	if c.DNSSEC.NSEC3Salt != "" {
		if _, err := hex.DecodeString(c.DNSSEC.NSEC3Salt); err != nil {
			return fmt.Errorf("nsec3_salt must be valid hex-encoded string: %w", err)
		}
		if len(c.DNSSEC.NSEC3Salt) > 510 { // 255 bytes max per RFC, times 2 for hex encoding
			return fmt.Errorf("nsec3_salt too long (max 255 bytes / 510 hex chars)")
		}
	}

	// Validate zone names and paths
	for domain, zone := range c.Zones {
		if err := ValidateDomainName(domain); err != nil {
			return fmt.Errorf("zone %q: %w", domain, err)
		}
		if zone.Path == "" {
			return fmt.Errorf("zone %q has no path specified", domain)
		}
		if _, err := os.Stat(zone.Path); os.IsNotExist(err) {
			return fmt.Errorf("zone file for %q does not exist: %s", domain, zone.Path)
		}
	}

	// Validate directories
	if c.OutputDir == "" {
		return fmt.Errorf("output_dir is required")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}

	return nil
}

// GetZoneKSKLifetime returns the KSK lifetime for a zone, using zone-specific override if set
func (c *Config) GetZoneKSKLifetime(domain string) time.Duration {
	if zone, ok := c.Zones[domain]; ok && zone.KSKLifetime.Duration > 0 {
		return zone.KSKLifetime.Duration
	}
	return c.DNSSEC.KSKLifetime.Duration
}

// GetZoneZSKLifetime returns the ZSK lifetime for a zone, using zone-specific override if set
func (c *Config) GetZoneZSKLifetime(domain string) time.Duration {
	if zone, ok := c.Zones[domain]; ok && zone.ZSKLifetime.Duration > 0 {
		return zone.ZSKLifetime.Duration
	}
	return c.DNSSEC.ZSKLifetime.Duration
}

// GetZoneAlgorithm returns the algorithm for a zone, using zone-specific override if set
func (c *Config) GetZoneAlgorithm(domain string) string {
	if zone, ok := c.Zones[domain]; ok && zone.Algorithm != "" {
		return zone.Algorithm
	}
	return c.DNSSEC.Algorithm
}

// KeysDir returns the path to the keys directory
func (c *Config) KeysDir() string {
	return filepath.Join(c.DataDir, "keys")
}

// StatePath returns the path to the state file
func (c *Config) StatePath() string {
	return filepath.Join(c.DataDir, "state.json")
}

// AddZoneToConfigFile appends a new zone entry to the config file
// This preserves existing formatting and comments by appending rather than rewriting
func AddZoneToConfigFile(configPath, domain, zonePath string) error {
	// Open config file for appending
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening config file: %w", err)
	}
	defer f.Close()

	// Append new zone section
	zoneEntry := fmt.Sprintf("\n[zones.%q]\npath = %q\n", domain, zonePath)
	if _, err := f.WriteString(zoneEntry); err != nil {
		return fmt.Errorf("writing zone entry: %w", err)
	}

	return nil
}

// RemoveZoneFromConfig removes a zone from the in-memory config
// Note: This does NOT modify the config file - that would require full rewriting
func (c *Config) RemoveZoneFromConfig(domain string) {
	delete(c.Zones, domain)
}

// ValidateDomainName checks that a domain name is safe for use in file paths.
// Rejects path traversal attempts and characters that are invalid in DNS names.
func ValidateDomainName(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain name must not be empty")
	}
	if strings.Contains(domain, "..") {
		return fmt.Errorf("domain name must not contain '..'")
	}
	if strings.ContainsAny(domain, "/\\") {
		return fmt.Errorf("domain name must not contain path separators")
	}
	// DNS names: letters, digits, hyphens, dots, and underscores (for SRV/DKIM)
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_') {
			return fmt.Errorf("domain name contains invalid character %q", c)
		}
	}
	return nil
}
