package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

// UnmarshalText implements encoding.TextUnmarshaler for Duration.
//
// Year/month/day suffixes are not supported by time.ParseDuration, so they are
// handled here. The numeric prefix must be a *complete* valid float:
// strconv.ParseFloat rejects trailing garbage like "1x2d" that the previous
// fmt.Sscanf("%f") would silently truncate to 1 (R-053).
func (d *Duration) UnmarshalText(text []byte) error {
	s := string(text)

	if len(s) > 0 {
		var unit float64
		switch s[len(s)-1] {
		case 'y', 'Y':
			unit = 365 * 24 * float64(time.Hour) // approximate: 365 days
		case 'M':
			unit = 30 * 24 * float64(time.Hour) // approximate: 30 days
		case 'd', 'D':
			unit = 24 * float64(time.Hour)
		}
		if unit != 0 {
			n, err := strconv.ParseFloat(s[:len(s)-1], 64)
			if err != nil {
				return fmt.Errorf("invalid duration %q: %w", s, err)
			}
			d.Duration = time.Duration(n * unit)
			return nil
		}
	}

	// Fall back to standard duration parsing (h/m/s, e.g. "5m", "90s").
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
	// Strict decoding: reject unknown/misspelled keys instead of silently
	// ignoring them. For a signing daemon a typo like `signture_validity` or a
	// key in the wrong table would otherwise revert crypto-timing/security
	// settings to defaults with no diagnostic (R-015). Every key in
	// testdata/README/QUICKSTART maps to a struct tag, so valid configs still load.
	dec := toml.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		var strictErr *toml.StrictMissingError
		if errors.As(err, &strictErr) {
			return nil, fmt.Errorf("parsing config file: unknown key(s):\n%s", strictErr.String())
		}
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	warnIfConfigWorldReadable(path, cfg)

	return cfg, nil
}

// warnIfConfigWorldReadable warns when the config carries registrar/heartbeat
// secrets but its file mode is looser than the documented 0640 (root-owned,
// group-readable by the daemon user). CLAUDE.md requires "mode 0640 or
// stricter"; a world-readable config with a Dynadot key/secret or heartbeat key
// is a real credential leak. We warn (rather than refuse) so a perms mistake
// never turns into a signing outage, but surface it loudly with remediation
// (R-052). The 0037 mask flags group-write and any other-access, while still
// permitting the allowed group-read bit of 0640.
func warnIfConfigWorldReadable(path string, cfg *Config) {
	hasSecrets := cfg.Registrar.Dynadot.APIKey != "" ||
		cfg.Registrar.Dynadot.APISecret != "" ||
		cfg.Heartbeat.APIKey != ""
	if !hasSecrets {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return // already read successfully above; a stat race here isn't worth failing on
	}
	if extra := info.Mode().Perm() & 0o037; extra != 0 {
		slog.Warn("[CONFIG] config holds secrets but is more permissive than 0640; tighten it",
			"path", path,
			"mode", fmt.Sprintf("%#o", info.Mode().Perm()),
			"remediation", fmt.Sprintf("chmod 0640 %s (and ensure it is root-owned)", path))
	}
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

	// R-029: DNS names are case-insensitive and an optional trailing root dot does
	// not change identity, but zone map keys / key filenames / state keys use the
	// operator's spelling verbatim. Reject a config where two entries collapse to the
	// same canonical identity (e.g. "example.com", "Example.COM", "example.com.")
	// before any signing or registrar action — otherwise they generate independent
	// KSK/DS sets for one DNS zone and can oscillate the parent's DS.
	seenCanonical := make(map[string]string, len(c.Zones))
	for domain := range c.Zones {
		id := canonicalZoneIdentity(domain)
		if prev, dup := seenCanonical[id]; dup {
			return fmt.Errorf("zones %q and %q refer to the same DNS zone %q; use a single canonical entry (lowercase, no trailing dot)", prev, domain, id)
		}
		seenCanonical[id] = domain
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

	// Rollover timings must be positive and correctly ordered (R-014). A
	// rollover_switch >= rollover_prepublish makes completion drop the old ZSK
	// on the next poll while resolvers still hold the DNSKEY RRset without the
	// new key — bogus for up to the DNSKEY TTL. Zero/negative collapses the
	// pre-publish safety window entirely.
	if c.DNSSEC.RolloverPrepublish.Duration <= 0 {
		return fmt.Errorf("rollover_prepublish must be positive")
	}
	if c.DNSSEC.RolloverSwitch.Duration <= 0 {
		return fmt.Errorf("rollover_switch must be positive")
	}
	if c.DNSSEC.RolloverSwitch.Duration >= c.DNSSEC.RolloverPrepublish.Duration {
		return fmt.Errorf("rollover_switch (%s) must be less than rollover_prepublish (%s)",
			c.DNSSEC.RolloverSwitch.String(), c.DNSSEC.RolloverPrepublish.String())
	}

	// Operational durations must be positive (R-013). A zero/negative
	// poll_interval panics time.NewTicker at startup and on SIGHUP; zero
	// timeouts disable the respective http.Client / graceful-shutdown deadlines.
	if c.PollInterval.Duration <= 0 {
		return fmt.Errorf("poll_interval must be positive")
	}
	if c.Health.ShutdownTimeout.Duration <= 0 {
		return fmt.Errorf("health.shutdown_timeout must be positive")
	}
	if c.Validation.Timeout.Duration <= 0 {
		return fmt.Errorf("validate.timeout must be positive")
	}
	if c.Registrar.Dynadot.Timeout.Duration <= 0 {
		return fmt.Errorf("registrar.dynadot.timeout must be positive")
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
		// A missing or otherwise unstattable zone file must NOT be fatal for the
		// whole config: one deleted/renamed/unmounted zone would otherwise refuse
		// startup entirely (a restart loop under Restart=on-failure while every
		// other zone's signatures march toward expiry — a total outage from one
		// bad entry). Warn and continue so the daemon starts and signs the other
		// zones; the broken one surfaces as a per-zone error in status/health once
		// signing runs. Covers both ENOENT and non-ENOENT stat errors (R-017).
		if _, err := os.Stat(zone.Path); err != nil {
			slog.Warn("[CONFIG] zone file is not accessible; the daemon will still start and sign the other zones",
				"domain", domain, "path", zone.Path, "error", err)
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

// AddZoneToConfigFile appends a new zone entry to the config file. It reads the
// existing bytes, appends the new [zones."<domain>"] table, and commits the whole
// file atomically and durably (temp + fsync + rename + dir fsync) while preserving
// the config's own owner/mode. The prior O_APPEND write was neither atomic nor
// durable — a short write or crash could leave a truncated table/header/path in the
// only config file after state/output were already committed (R-019). Existing
// tables/comments are preserved verbatim (only appended to).
func AddZoneToConfigFile(configPath, domain, zonePath string) error {
	existing, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	// Append the new zone section, matching the previous formatting (a leading blank
	// line before the table). Ensure exactly one separating newline regardless of
	// whether the file already ends in one.
	buf := make([]byte, 0, len(existing)+128)
	buf = append(buf, existing...)
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	buf = append(buf, []byte(fmt.Sprintf("\n[zones.%q]\npath = %q\n", domain, zonePath))...)

	if err := writeConfigFileAtomic(configPath, buf); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}
	return nil
}

// RemoveZoneFromConfigFile deletes the [zones."<domain>"] table (the header written by
// AddZoneToConfigFile plus every key line under it) from the config file, preserving all
// other content and comments. It writes atomically (temp + rename, ownership preserved)
// and keeps the file's existing mode so a secrets-bearing 0640 config is not loosened.
// Returns errZoneNotInConfig if the table isn't present, so the caller can proceed.
func RemoveZoneFromConfigFile(configPath, domain string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}
	lines := strings.Split(string(data), "\n")

	start := -1
	for i, line := range lines {
		if isZoneTableHeader(line, domain) {
			start = i
			break
		}
	}
	if start == -1 {
		return errZoneNotInConfig
	}

	// The table runs until the next TOML table header or EOF.
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if isTOMLTableHeader(lines[i]) {
			end = i
			break
		}
	}

	// Absorb one blank line immediately preceding the table (AddZoneToConfigFile prefixes
	// one) so repeated add/remove cycles don't accumulate blank runs.
	removeStart := start
	if removeStart > 0 && strings.TrimSpace(lines[removeStart-1]) == "" {
		removeStart--
	}

	kept := make([]string, 0, len(lines)-(end-removeStart))
	kept = append(kept, lines[:removeStart]...)
	kept = append(kept, lines[end:]...)

	// R-002: use the config-specific atomic writer, which preserves the config's
	// OWN uid/gid/mode. writeFileAtomicOwned would chown the (root-owned, secrets-
	// bearing) config to the daemon account.
	if err := writeConfigFileAtomic(configPath, []byte(strings.Join(kept, "\n"))); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}
	return nil
}

// errZoneNotInConfig is returned by RemoveZoneFromConfigFile when the zone table is absent.
var errZoneNotInConfig = fmt.Errorf("zone table not found in config file")

// isZoneTableHeader reports whether a config line is the [zones."<domain>"]
// table header for the given domain. AddZoneToConfigFile writes exactly
// `[zones."<domain>"]`, but hand-edited configs carry TOML-equivalent variants
// an exact match would miss: surrounding whitespace, a trailing `# comment`,
// or a single-quoted (literal-string) key. Missing the header would make
// `remove` leave the entry behind so the zone is re-adopted on SIGHUP
// (runRemove escalates that to an error rather than claiming success). This is
// deliberately anchored to the two quote forms — not a general TOML parser.
func isZoneTableHeader(line, domain string) bool {
	t := strings.TrimSpace(line)
	for _, header := range []string{
		fmt.Sprintf("[zones.%q]", domain),   // basic-string key, what AddZoneToConfigFile writes
		fmt.Sprintf("[zones.'%s']", domain), // literal-string key
	} {
		rest, ok := strings.CutPrefix(t, header)
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if rest == "" || strings.HasPrefix(rest, "#") {
			return true
		}
	}
	return false
}

// isTOMLTableHeader reports whether a line is a TOML table header — a normal table
// "[...]" or an array-of-tables "[[...]]" — allowing surrounding whitespace, quoted/
// dotted keys (basic "..." or literal '...' strings that may themselves contain '#'
// or ']'), and a trailing inline comment. The previous HasPrefix("[")+HasSuffix("]")
// test wrongly rejected a valid header followed by a comment (e.g.
// `[zones."next"] # x`), which made RemoveZoneFromConfigFile run past that boundary
// and delete every following table/comment through EOF (R-001).
func isTOMLTableHeader(line string) bool {
	t := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(t, "[") {
		return false
	}
	array := strings.HasPrefix(t, "[[")
	i := 1
	if array {
		i = 2
	}
	inBasic, inLiteral := false, false
	for i < len(t) {
		c := t[i]
		switch {
		case inBasic:
			if c == '\\' && i+1 < len(t) {
				i += 2
				continue
			}
			if c == '"' {
				inBasic = false
			}
		case inLiteral:
			if c == '\'' {
				inLiteral = false
			}
		default:
			switch c {
			case '"':
				inBasic = true
			case '\'':
				inLiteral = true
			case ']':
				if array {
					if i+1 < len(t) && t[i+1] == ']' {
						return afterHeaderIsCommentOrBlank(t[i+2:])
					}
					return false // single ']' cannot close an array-of-tables header
				}
				return afterHeaderIsCommentOrBlank(t[i+1:])
			}
		}
		i++
	}
	return false
}

// afterHeaderIsCommentOrBlank reports whether the text following a table header's
// closing bracket(s) is only whitespace and an optional inline comment.
func afterHeaderIsCommentOrBlank(rest string) bool {
	rest = strings.TrimSpace(rest)
	return rest == "" || strings.HasPrefix(rest, "#")
}

// canonicalZoneIdentity returns the case- and trailing-dot-normalized management
// identity for a zone name: lowercase with any trailing root dot removed (R-029).
// Two operator spellings that denote the same DNS zone map to the same identity.
func canonicalZoneIdentity(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

// canonicalConflict reports whether domain canonically matches (case- and
// trailing-dot-insensitively) any zone already present in the config or state,
// other than an exact match (which callers check separately). Returns the
// conflicting existing name (R-029).
func canonicalConflict(cfg *Config, state *State, domain string) (string, bool) {
	id := canonicalZoneIdentity(domain)
	for existing := range cfg.Zones {
		if existing != domain && canonicalZoneIdentity(existing) == id {
			return existing, true
		}
	}
	for _, existing := range state.ZoneNames() {
		if existing != domain && canonicalZoneIdentity(existing) == id {
			return existing, true
		}
	}
	return "", false
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
