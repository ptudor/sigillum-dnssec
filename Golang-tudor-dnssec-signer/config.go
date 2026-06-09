package main

import (
	"encoding/hex"
	"fmt"
	"net"
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
	Validation   ValidateConfig        `toml:"validate"`
	Zones        map[string]ZoneConfig `toml:"zones"`
	Hooks        HooksConfig           `toml:"hooks"`
	Registrar    RegistrarConfig       `toml:"registrar"`
}

// RegistrarConfig groups all registrar adapter settings. Each sub-struct is
// opt-in via its own Enabled field; a zone binds to one adapter by name via
// ZoneConfig.Registrar.
type RegistrarConfig struct {
	DigestTypeVal int                    `toml:"digest_type"` // 2 = SHA-256 (default), 4 = SHA-384
	Dynadot       RegistrarDynadotConfig `toml:"dynadot"`
}

// DigestType returns the DS digest algorithm to use when pushing DS records.
// Defaults to SHA-256 (type 2) when unset or invalid.
func (r RegistrarConfig) DigestType() uint8 {
	switch r.DigestTypeVal {
	case 4:
		return 4
	default:
		return 2
	}
}

// RegistrarDynadotConfig holds settings for the Dynadot API adapter.
//
// The restful/v2 API requires both a key and a secret: the key goes in the
// Authorization header, the secret is the HMAC-SHA256 key used to compute
// the X-Signature header. Both are issued under Tools → API in the Dynadot
// control panel (separate values for sandbox vs production).
type RegistrarDynadotConfig struct {
	Enabled     bool     `toml:"enabled"`
	APIKey      string   `toml:"api_key"`      // required; keep config file mode 0640 or stricter
	APISecret   string   `toml:"api_secret"`   // required; HMAC key for X-Signature
	Sandbox     bool     `toml:"sandbox"`      // true → api-sandbox.dynadot.com
	Timeout     Duration `toml:"timeout"`      // default 30s
	AutoPublish bool     `toml:"auto_publish"` // push DS automatically on add/rollover events
	UserAgent   string   `toml:"user_agent"`   // override the default dnssec-tudor/<version> UA
	// SendRequestID defaults to false because Dynadot's "X-Signature
	// invalid" errors appear to correlate with header-case mismatches:
	// Go HTTP/2 sends `x-request-id` (lowercase) while their docs
	// spell `X-Request-ID` (uppercase ID). If their handler is
	// case-sensitive it treats the header as absent and signs with
	// empty string, producing the signature mismatch we see. When
	// this flag is false, the adapter omits the header and signs with
	// empty requestID, which is what Dynadot expects in the "absent"
	// case. Set true only if Dynadot confirms they read the header.
	SendRequestID bool `toml:"send_request_id"`
}

// ValidateConfig holds settings for internet DNSSEC validation checks
type ValidateConfig struct {
	Resolver string   `toml:"resolver"` // e.g. "8.8.8.8:53", default: system resolver
	Timeout  Duration `toml:"timeout"`  // default: 5s
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
	AllowInsecure   bool   `toml:"allow_insecure"` // Allow non-HTTPS heartbeat URL
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
	// SerialPolicy controls the SOA serial written to signed zones:
	//   "keep"  — publish the unsigned zone's serial unchanged (default)
	//   "epoch" — publish max(now, serial+1, last_published+1) so every
	//             signing event (including signature refreshes that don't
	//             touch the unsigned file) is visible to AXFR/IXFR
	//             secondaries. Zones under this policy MUST use unix epoch
	//             serials in the unsigned file; date-format serials
	//             (YYYYMMDDnn) are rejected at signing time because they
	//             exceed the current epoch and would move serials backwards.
	SerialPolicy string `toml:"serial_policy"`
}

// WebConfig holds web UI settings
type WebConfig struct {
	Enabled     bool   `toml:"enabled"`
	Listen      string `toml:"listen"`
	AllowRemote bool   `toml:"allow_remote"` // Must be true to bind non-loopback addresses
}

// HealthConfig holds health server settings
type HealthConfig struct {
	Listen          string   `toml:"listen"`
	ShutdownTimeout Duration `toml:"shutdown_timeout"`
	AllowRemote     bool     `toml:"allow_remote"` // Must be true to bind non-loopback addresses
	DebugVars       bool     `toml:"debug_vars"`   // Enable /debug/vars endpoint (default false)
}

// ZoneConfig holds per-zone settings
type ZoneConfig struct {
	Path         string   `toml:"path"`
	KSKLifetime  Duration `toml:"ksk_lifetime,omitempty"`
	ZSKLifetime  Duration `toml:"zsk_lifetime,omitempty"`
	Algorithm    string   `toml:"algorithm,omitempty"`     // Per-zone algorithm override for algorithm rollover
	Registrar    string   `toml:"registrar,omitempty"`     // Opt-in registrar adapter name, e.g. "dynadot"
	SerialPolicy string   `toml:"serial_policy,omitempty"` // Per-zone override: "keep" or "epoch"
}

// HooksConfig holds hook settings
type HooksConfig struct {
	PostSign         string   `toml:"post_sign"`          // Shell command (requires shell = true) or simple command
	PostSignCmd      []string `toml:"post_sign_cmd"`      // Exec-style command+args (preferred, no shell)
	Shell            bool     `toml:"shell"`              // Use sh -c for post_sign string (default false)
	CoalescePostSign bool     `toml:"coalesce_post_sign"` // Fire hook once per cycle after all zones sign, with DNSSEC_DOMAINS set
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
			KSKLifetime:        Duration{5 * 365 * 24 * time.Hour}, // 5 years
			ZSKLifetime:        Duration{90 * 24 * time.Hour},      // 90 days
			SignatureValidity:  Duration{14 * 24 * time.Hour},      // 14 days
			SignatureRefresh:   Duration{3 * 24 * time.Hour},       // 3 days
			NSECVersion:        "nsec3",
			NSEC3Iterations:    0,
			NSEC3Salt:          "",
			DNSKEYTtl:          0,                             // 0 = use SOA TTL
			RolloverPrepublish: Duration{14 * 24 * time.Hour}, // 14 days before expiry
			RolloverSwitch:     Duration{7 * 24 * time.Hour},  // 7 days to switch signing
			SerialPolicy:       "keep",
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
		Validation: ValidateConfig{
			Timeout: Duration{5 * time.Second},
		},
		Zones: make(map[string]ZoneConfig),
		Hooks: HooksConfig{},
		Registrar: RegistrarConfig{
			DigestTypeVal: 2,
			Dynadot: RegistrarDynadotConfig{
				Enabled:     false,
				Timeout:     Duration{30 * time.Second},
				AutoPublish: true,
			},
		},
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

	// Validate serial policy (global and per-zone)
	validSerialPolicies := map[string]bool{"": true, "keep": true, "epoch": true}
	if !validSerialPolicies[c.DNSSEC.SerialPolicy] {
		return fmt.Errorf("serial_policy must be 'keep' or 'epoch', got %q", c.DNSSEC.SerialPolicy)
	}
	for domain, zone := range c.Zones {
		if !validSerialPolicies[zone.SerialPolicy] {
			return fmt.Errorf("zone %q: serial_policy must be 'keep' or 'epoch', got %q", domain, zone.SerialPolicy)
		}
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
		if zone.Registrar != "" {
			switch strings.ToLower(zone.Registrar) {
			case "dynadot":
				if !c.Registrar.Dynadot.Enabled {
					return fmt.Errorf("zone %q references registrar=\"dynadot\" but [registrar.dynadot] is not enabled", domain)
				}
			default:
				return fmt.Errorf("zone %q references unknown registrar %q (supported: dynadot)", domain, zone.Registrar)
			}
		}
	}

	// Validate directories
	if c.OutputDir == "" {
		return fmt.Errorf("output_dir is required")
	}
	if c.DataDir == "" {
		return fmt.Errorf("data_dir is required")
	}

	// Validate heartbeat URL is HTTPS unless allow_insecure is set
	if c.Heartbeat.Enabled && c.Heartbeat.URL != "" && !c.Heartbeat.AllowInsecure {
		if !strings.HasPrefix(c.Heartbeat.URL, "https://") {
			return fmt.Errorf("heartbeat.url must use HTTPS (got %q); set allow_insecure = true to override", c.Heartbeat.URL)
		}
	}

	// Validate listen addresses are loopback unless allow_remote is set
	if c.Web.Enabled && !c.Web.AllowRemote {
		if err := validateLoopbackAddr(c.Web.Listen, "web.listen"); err != nil {
			return err
		}
	}
	if !c.Health.AllowRemote {
		if err := validateLoopbackAddr(c.Health.Listen, "health.listen"); err != nil {
			return err
		}
	}

	return nil
}

// isLoopbackAddr returns true if the host part of an address is a loopback address.
// Accepts "host:port", ":port" (all interfaces — NOT loopback), or "host" forms.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr // No port, treat whole string as host
	}
	// Empty host means all interfaces (e.g., ":8053") — not loopback
	if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Could be "localhost"
		return strings.EqualFold(host, "localhost")
	}
	return ip.IsLoopback()
}

// validateLoopbackAddr returns an error if the listen address is not loopback
func validateLoopbackAddr(addr, fieldName string) error {
	if !isLoopbackAddr(addr) {
		return fmt.Errorf("%s %q binds to a non-loopback address; set allow_remote = true to allow this", fieldName, addr)
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

// GetZoneSerialPolicy returns the serial policy for a zone, using the
// zone-specific override if set. Defaults to "keep".
func (c *Config) GetZoneSerialPolicy(domain string) string {
	if zone, ok := c.Zones[domain]; ok && zone.SerialPolicy != "" {
		return zone.SerialPolicy
	}
	if c.DNSSEC.SerialPolicy != "" {
		return c.DNSSEC.SerialPolicy
	}
	return "keep"
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
