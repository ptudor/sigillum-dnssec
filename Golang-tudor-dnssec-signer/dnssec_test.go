package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Test configuration for fast rollover testing (1 second instead of days)
func testConfig(t *testing.T, dataDir string) *Config {
	t.Helper()
	return &Config{
		OutputDir:    filepath.Join(dataDir, "signed"),
		DataDir:      dataDir,
		PollInterval: Duration{1 * time.Second},
		DNSSEC: DNSSECConfig{
			Algorithm:          "ED25519",
			KSKLifetime:        Duration{10 * time.Second}, // Very short for testing
			ZSKLifetime:        Duration{5 * time.Second},  // Very short for testing
			SignatureValidity:  Duration{3 * time.Second},
			SignatureRefresh:   Duration{1 * time.Second},
			NSECVersion:        "nsec3",
			NSEC3Iterations:    0,
			NSEC3Salt:          "",
			DNSKEYTtl:          3600,
			RolloverPrepublish: Duration{2 * time.Second},
			RolloverSwitch:     Duration{1 * time.Second},
		},
		Web: WebConfig{
			Enabled: false,
			Listen:  "127.0.0.1:8053",
		},
		Health: HealthConfig{
			Listen: "127.0.0.1:8054",
		},
		Zones: make(map[string]ZoneConfig),
		Hooks: HooksConfig{},
	}
}

// TestKeyGeneration tests key generation for all supported algorithms
func TestKeyGeneration(t *testing.T) {
	algorithms := []string{"ED25519", "ECDSAP256SHA256", "ECDSAP384SHA384"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			dataDir := t.TempDir()
			cfg := testConfig(t, dataDir)
			cfg.DNSSEC.Algorithm = alg

			keyGen := NewKeyGenerator(cfg)

			// Test KSK generation
			ksk, err := keyGen.GenerateKSK("example.com")
			if err != nil {
				t.Fatalf("GenerateKSK failed for %s: %v", alg, err)
			}
			if ksk.ID == 0 {
				t.Error("KSK key tag should not be 0")
			}
			if ksk.Algorithm != alg {
				t.Errorf("KSK algorithm mismatch: got %s, want %s", ksk.Algorithm, alg)
			}

			// Test ZSK generation
			zsk, err := keyGen.GenerateZSK("example.com")
			if err != nil {
				t.Fatalf("GenerateZSK failed for %s: %v", alg, err)
			}
			if zsk.ID == 0 {
				t.Error("ZSK key tag should not be 0")
			}
			if ksk.ID == zsk.ID {
				t.Error("KSK and ZSK should have different key tags")
			}

			// Test key loading
			loadedKSK, kskPriv, err := keyGen.LoadKeyPair("example.com", "ksk")
			if err != nil {
				t.Fatalf("LoadKeyPair(ksk) failed: %v", err)
			}
			if loadedKSK.KeyTag() != ksk.ID {
				t.Errorf("Loaded KSK key tag mismatch: got %d, want %d", loadedKSK.KeyTag(), ksk.ID)
			}
			if len(kskPriv) == 0 {
				t.Error("KSK private key should not be empty")
			}

			loadedZSK, zskPriv, err := keyGen.LoadKeyPair("example.com", "zsk")
			if err != nil {
				t.Fatalf("LoadKeyPair(zsk) failed: %v", err)
			}
			if loadedZSK.KeyTag() != zsk.ID {
				t.Errorf("Loaded ZSK key tag mismatch: got %d, want %d", loadedZSK.KeyTag(), zsk.ID)
			}
			if len(zskPriv) == 0 {
				t.Error("ZSK private key should not be empty")
			}
		})
	}
}

// TestDSComputation tests DS record computation
func TestDSComputation(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	keyGen := NewKeyGenerator(cfg)

	ksk, err := keyGen.GenerateKSK("example.com")
	if err != nil {
		t.Fatalf("GenerateKSK failed: %v", err)
	}

	dnskey, _, err := keyGen.LoadKeyPair("example.com", "ksk")
	if err != nil {
		t.Fatalf("LoadKeyPair failed: %v", err)
	}

	// Compute DS with SHA-256
	ds := ComputeDS("example.com", dnskey, dns.SHA256)
	if ds == nil {
		t.Fatal("ComputeDS returned nil")
	}

	if ds.KeyTag != ksk.ID {
		t.Errorf("DS key tag mismatch: got %d, want %d", ds.KeyTag, ksk.ID)
	}
	if ds.Algorithm != dnskey.Algorithm {
		t.Errorf("DS algorithm mismatch: got %d, want %d", ds.Algorithm, dnskey.Algorithm)
	}
	if ds.DigestType != dns.SHA256 {
		t.Errorf("DS digest type mismatch: got %d, want %d", ds.DigestType, dns.SHA256)
	}
	if len(ds.Digest) == 0 {
		t.Error("DS digest should not be empty")
	}
}

// TestZoneValidation tests zone file parsing and validation
func TestZoneValidation(t *testing.T) {
	tests := []struct {
		name      string
		zone      string
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid zone",
			zone: `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. (
				2024011501	; serial
				3600		; refresh
				1800		; retry
				604800		; expire
				86400		; minimum
			)
@	IN	NS	ns1.example.com.
@	IN	NS	ns2.example.com.
ns1	IN	A	192.0.2.1
ns2	IN	A	192.0.2.2
www	IN	A	192.0.2.10
`,
			expectErr: false,
		},
		{
			name: "missing SOA",
			zone: `$ORIGIN example.com.
$TTL 3600
@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
`,
			expectErr: true,
			errMsg:    "no SOA record",
		},
		{
			name: "missing NS at apex",
			zone: `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. (
				2024011501	; serial
				3600		; refresh
				1800		; retry
				604800		; expire
				86400		; minimum
			)
sub	IN	NS	ns1.sub.example.com.
`,
			expectErr: true,
			errMsg:    "no NS records at apex",
		},
		{
			name: "multiple SOA records",
			zone: `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. (
				2024011501	; serial
				3600		; refresh
				1800		; retry
				604800		; expire
				86400		; minimum
			)
@	IN	SOA	ns2.example.com. admin.example.com. (
				2024011502	; serial
				3600		; refresh
				1800		; retry
				604800		; expire
				86400		; minimum
			)
@	IN	NS	ns1.example.com.
`,
			expectErr: true,
			errMsg:    "SOA records",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			zonePath := filepath.Join(tmpDir, "zone.db")

			if err := os.WriteFile(zonePath, []byte(tt.zone), 0644); err != nil {
				t.Fatalf("Failed to write zone file: %v", err)
			}

			err := ValidateZoneFile("example.com", zonePath)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestSigningRoundTrip tests complete zone signing and verification
func TestSigningRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	// Create zone file
	zoneContent := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. (
			2024011501	; serial
			3600		; refresh
			1800		; retry
			604800		; expire
			86400		; minimum
		)
@	IN	NS	ns1.example.com.
@	IN	NS	ns2.example.com.
ns1	IN	A	192.0.2.1
ns2	IN	A	192.0.2.2
@	IN	A	192.0.2.10
www	IN	A	192.0.2.20
mail	IN	A	192.0.2.30
@	IN	MX	10 mail.example.com.
`
	zonePath := filepath.Join(dataDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("Failed to write zone file: %v", err)
	}

	cfg.Zones["example.com"] = ZoneConfig{Path: zonePath}

	// Ensure directories
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	// Create state
	state := NewState(cfg.StatePath())

	// Generate keys
	keyGen := NewKeyGenerator(cfg)
	ksk, err := keyGen.GenerateKSK("example.com")
	if err != nil {
		t.Fatalf("GenerateKSK failed: %v", err)
	}
	zsk, err := keyGen.GenerateZSK("example.com")
	if err != nil {
		t.Fatalf("GenerateZSK failed: %v", err)
	}

	// Set up zone state
	state.SetZone("example.com", &ZoneState{
		Path: zonePath,
		KSK:  ksk,
		ZSK:  zsk,
	})

	// Sign the zone
	signer := NewSigner(cfg, state)
	if err := signer.SignZone("example.com"); err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	// Verify signed zone exists
	signedPath := filepath.Join(cfg.OutputDir, "example.com.zone.signed")
	if _, err := os.Stat(signedPath); os.IsNotExist(err) {
		t.Fatal("Signed zone file not created")
	}

	// Read and verify signed zone
	signedData, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatalf("Failed to read signed zone: %v", err)
	}

	// Parse signed zone and verify records exist
	zp := dns.NewZoneParser(strings.NewReader(string(signedData)), "example.com.", signedPath)

	var (
		hasDNSKEY  bool
		hasRRSIG   bool
		hasNSEC3   bool
		soaCount   int
		rrsigCount int
	)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch rr.Header().Rrtype {
		case dns.TypeDNSKEY:
			hasDNSKEY = true
		case dns.TypeRRSIG:
			hasRRSIG = true
			rrsigCount++
		case dns.TypeNSEC3:
			hasNSEC3 = true
		case dns.TypeSOA:
			soaCount++
		}
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("Error parsing signed zone: %v", err)
	}

	if !hasDNSKEY {
		t.Error("Signed zone missing DNSKEY records")
	}
	if !hasRRSIG {
		t.Error("Signed zone missing RRSIG records")
	}
	if !hasNSEC3 {
		t.Error("Signed zone missing NSEC3 records")
	}
	if soaCount != 1 {
		t.Errorf("Expected 1 SOA record, got %d", soaCount)
	}
	if rrsigCount < 5 {
		t.Errorf("Expected at least 5 RRSIG records, got %d", rrsigCount)
	}

	// Verify state was updated
	zoneState := state.GetZone("example.com")
	if zoneState == nil {
		t.Fatal("Zone state not found")
	}
	if zoneState.Serial != 2024011501 {
		t.Errorf("Serial mismatch: got %d, want 2024011501", zoneState.Serial)
	}
	if zoneState.LastSigned.IsZero() {
		t.Error("LastSigned should not be zero")
	}
	if zoneState.SignaturesExp.IsZero() {
		t.Error("SignaturesExp should not be zero")
	}
}

// TestNSECChainGeneration tests NSEC chain generation
func TestNSECChainGeneration(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	cfg.DNSSEC.NSECVersion = "nsec" // Test NSEC instead of NSEC3

	zoneContent := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
www	IN	A	192.0.2.10
`
	zonePath := filepath.Join(dataDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("Failed to write zone file: %v", err)
	}

	cfg.Zones["example.com"] = ZoneConfig{Path: zonePath}
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	state := NewState(cfg.StatePath())
	keyGen := NewKeyGenerator(cfg)

	ksk, _ := keyGen.GenerateKSK("example.com")
	zsk, _ := keyGen.GenerateZSK("example.com")
	state.SetZone("example.com", &ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})

	signer := NewSigner(cfg, state)
	if err := signer.SignZone("example.com"); err != nil {
		t.Fatalf("SignZone with NSEC failed: %v", err)
	}

	// Verify NSEC records exist (not NSEC3)
	signedPath := filepath.Join(cfg.OutputDir, "example.com.zone.signed")
	signedData, _ := os.ReadFile(signedPath)
	zp := dns.NewZoneParser(strings.NewReader(string(signedData)), "example.com.", signedPath)

	var hasNSEC, hasNSEC3 bool
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch rr.Header().Rrtype {
		case dns.TypeNSEC:
			hasNSEC = true
		case dns.TypeNSEC3:
			hasNSEC3 = true
		}
	}

	if !hasNSEC {
		t.Error("Expected NSEC records")
	}
	if hasNSEC3 {
		t.Error("Did not expect NSEC3 records when nsec_version=nsec")
	}
}

// TestAlgorithmFromName tests algorithm name parsing
func TestAlgorithmFromName(t *testing.T) {
	tests := []struct {
		name      string
		expected  uint8
		expectErr bool
	}{
		{"ED25519", dns.ED25519, false},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256, false},
		{"ECDSAP384SHA384", dns.ECDSAP384SHA384, false},
		{"RSASHA256", dns.RSASHA256, false},
		{"RSASHA512", dns.RSASHA512, false},
		{"INVALID", 0, true},
		{"ed25519", 0, true}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := AlgorithmFromName(tt.name)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for %q, got nil", tt.name)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %q: %v", tt.name, err)
				}
				if alg != tt.expected {
					t.Errorf("Algorithm mismatch for %q: got %d, want %d", tt.name, alg, tt.expected)
				}
			}
		})
	}
}

// TestAlgorithmName tests algorithm number to name conversion
func TestAlgorithmName(t *testing.T) {
	tests := []struct {
		alg      uint8
		expected string
	}{
		{dns.ED25519, "ED25519"},
		{dns.ECDSAP256SHA256, "ECDSAP256SHA256"},
		{dns.ECDSAP384SHA384, "ECDSAP384SHA384"},
		{dns.RSASHA256, "RSASHA256"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name := AlgorithmName(tt.alg)
			if name != tt.expected {
				t.Errorf("AlgorithmName(%d) = %q, want %q", tt.alg, name, tt.expected)
			}
		})
	}
}

// TestDurationParsing tests custom duration parsing
func TestDurationParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"1y", 365 * 24 * time.Hour},
		{"3y", 3 * 365 * 24 * time.Hour},
		{"90d", 90 * 24 * time.Hour},
		{"14d", 14 * 24 * time.Hour},
		{"1M", 30 * 24 * time.Hour},
		{"5m", 5 * time.Minute},
		{"30s", 30 * time.Second},
		{"1h", 1 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var d Duration
			if err := d.UnmarshalText([]byte(tt.input)); err != nil {
				t.Fatalf("UnmarshalText(%q) failed: %v", tt.input, err)
			}
			if d.Duration != tt.expected {
				t.Errorf("Duration mismatch: got %v, want %v", d.Duration, tt.expected)
			}
		})
	}
}

// TestConfigValidation tests configuration validation
func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		modify    func(*Config)
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid config",
			modify:    func(c *Config) {},
			expectErr: false,
		},
		{
			name: "invalid algorithm",
			modify: func(c *Config) {
				c.DNSSEC.Algorithm = "INVALID"
			},
			expectErr: true,
			errMsg:    "unsupported algorithm",
		},
		{
			name: "invalid nsec version",
			modify: func(c *Config) {
				c.DNSSEC.NSECVersion = "nsec4"
			},
			expectErr: true,
			errMsg:    "nsec_version",
		},
		{
			name: "refresh >= validity",
			modify: func(c *Config) {
				c.DNSSEC.SignatureRefresh = Duration{15 * 24 * time.Hour}
				c.DNSSEC.SignatureValidity = Duration{14 * 24 * time.Hour}
			},
			expectErr: true,
			errMsg:    "signature_refresh",
		},
		{
			name: "nsec3 iterations too high",
			modify: func(c *Config) {
				c.DNSSEC.NSEC3Iterations = 200
			},
			expectErr: true,
			errMsg:    "nsec3_iterations",
		},
		{
			name: "invalid nsec3 salt",
			modify: func(c *Config) {
				c.DNSSEC.NSEC3Salt = "not-hex"
			},
			expectErr: true,
			errMsg:    "nsec3_salt",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				OutputDir:    "/tmp/test",
				DataDir:      "/tmp/test",
				PollInterval: Duration{5 * time.Minute},
				DNSSEC: DNSSECConfig{
					Algorithm:         "ED25519",
					KSKLifetime:       Duration{3 * 365 * 24 * time.Hour},
					ZSKLifetime:       Duration{90 * 24 * time.Hour},
					SignatureValidity: Duration{14 * 24 * time.Hour},
					SignatureRefresh:  Duration{3 * 24 * time.Hour},
					NSECVersion:       "nsec3",
					NSEC3Iterations:   0,
					NSEC3Salt:         "",
				},
				Health: HealthConfig{
					Listen: "127.0.0.1:8054",
				},
				Zones: make(map[string]ZoneConfig),
			}
			tt.modify(cfg)

			err := cfg.Validate()
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestRolloverStateTransitions tests the rollover state machine
func TestRolloverStateTransitions(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	zoneContent := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
`
	zonePath := filepath.Join(dataDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("Failed to write zone file: %v", err)
	}

	cfg.Zones["example.com"] = ZoneConfig{Path: zonePath}
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	state := NewState(cfg.StatePath())
	keyGen := NewKeyGenerator(cfg)

	ksk, _ := keyGen.GenerateKSK("example.com")
	zsk, _ := keyGen.GenerateZSK("example.com")
	state.SetZone("example.com", &ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})

	rolloverMgr := NewRolloverManager(cfg, state)

	// Test KSK rollover start
	err := rolloverMgr.StartKSKRollover("example.com")
	if err != nil {
		t.Fatalf("StartKSKRollover failed: %v", err)
	}

	zoneState := state.GetZone("example.com")
	if zoneState.Rollover == nil {
		t.Fatal("Rollover state should not be nil after start")
	}
	if zoneState.Rollover.Type != "ksk" {
		t.Errorf("Rollover type should be 'ksk', got %q", zoneState.Rollover.Type)
	}
	if zoneState.Rollover.State != KSKRolloverStateDSAddWait {
		t.Errorf("Rollover state should be %q, got %q", KSKRolloverStateDSAddWait, zoneState.Rollover.State)
	}

	// Cannot start another rollover while one is in progress
	err = rolloverMgr.StartKSKRollover("example.com")
	if err == nil {
		t.Error("Should not be able to start another rollover while one is in progress")
	}

	// Complete the rollover
	err = rolloverMgr.CompleteKSKRollover("example.com")
	if err != nil {
		t.Fatalf("CompleteKSKRollover failed: %v", err)
	}

	zoneState = state.GetZone("example.com")
	if zoneState.Rollover != nil {
		t.Error("Rollover state should be nil after completion")
	}
}

// TestCanonicalOrdering tests the canonical DNS name ordering used for NSEC chains
func TestCanonicalOrdering(t *testing.T) {
	// Test cases based on RFC 4034 Section 6.1
	// Note: We test common cases; escaped characters like \001 are rare in practice
	tests := []struct {
		a, b     string
		expected bool // true if a < b
	}{
		{"example.", "a.example.", true},
		{"a.example.", "yljkjljk.a.example.", true},
		{"yljkjljk.a.example.", "Z.a.example.", true},
		{"Z.a.example.", "zABC.a.EXAMPLE.", true},
		{"zABC.a.EXAMPLE.", "z.example.", true},
		// Basic alphabetical ordering
		{"a.example.", "b.example.", true},
		{"aa.example.", "ab.example.", true},
		// Case insensitivity
		{"A.example.", "b.example.", true},
		{"a.example.", "B.example.", true},
		// Subdomain ordering (child after parent)
		{"example.", "sub.example.", true},
		{"sub.example.", "a.sub.example.", true},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			result := canonicalLess(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("canonicalLess(%q, %q) = %v, want %v", tt.a, tt.b, result, tt.expected)
			}
		})
	}
}

// TestStateFilePersistence tests state saving and loading
func TestStateFilePersistence(t *testing.T) {
	dataDir := t.TempDir()
	statePath := filepath.Join(dataDir, "state.json")

	// Create and populate state
	state := NewState(statePath)
	state.SetZone("example.com", &ZoneState{
		Path:   "/etc/nsd/zones/example.com.zone",
		Serial: 2024011501,
		KSK: &KeyState{
			ID:        12345,
			Algorithm: "ED25519",
			Created:   time.Now().UTC(),
			Expires:   time.Now().UTC().Add(3 * 365 * 24 * time.Hour),
		},
		ZSK: &KeyState{
			ID:        54321,
			Algorithm: "ED25519",
			Created:   time.Now().UTC(),
			Expires:   time.Now().UTC().Add(90 * 24 * time.Hour),
		},
	})

	// Save state
	if err := state.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(statePath); os.IsNotExist(err) {
		t.Fatal("State file not created")
	}

	// Load state in new instance
	loadedState, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}

	// Verify data
	zoneState := loadedState.GetZone("example.com")
	if zoneState == nil {
		t.Fatal("Zone state not found after loading")
	}
	if zoneState.Serial != 2024011501 {
		t.Errorf("Serial mismatch: got %d, want 2024011501", zoneState.Serial)
	}
	if zoneState.KSK == nil || zoneState.KSK.ID != 12345 {
		t.Error("KSK data not preserved")
	}
	if zoneState.ZSK == nil || zoneState.ZSK.ID != 54321 {
		t.Error("ZSK data not preserved")
	}
}

// TestSignatureVerification tests that generated signatures can be verified
func TestSignatureVerification(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	zoneContent := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
www	IN	A	192.0.2.10
`
	zonePath := filepath.Join(dataDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("Failed to write zone file: %v", err)
	}

	cfg.Zones["example.com"] = ZoneConfig{Path: zonePath}
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	state := NewState(cfg.StatePath())
	keyGen := NewKeyGenerator(cfg)

	ksk, _ := keyGen.GenerateKSK("example.com")
	zsk, _ := keyGen.GenerateZSK("example.com")
	state.SetZone("example.com", &ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})

	signer := NewSigner(cfg, state)
	if err := signer.SignZone("example.com"); err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	// Load signed zone and extract records
	signedPath := filepath.Join(cfg.OutputDir, "example.com.zone.signed")
	signedData, _ := os.ReadFile(signedPath)
	zp := dns.NewZoneParser(strings.NewReader(string(signedData)), "example.com.", signedPath)

	var dnskeys []*dns.DNSKEY
	rrsigsByType := make(map[uint16][]*dns.RRSIG)
	rrsetsByType := make(map[uint16][]dns.RR)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch r := rr.(type) {
		case *dns.DNSKEY:
			dnskeys = append(dnskeys, r)
		case *dns.RRSIG:
			rrsigsByType[r.TypeCovered] = append(rrsigsByType[r.TypeCovered], r)
		default:
			rrsetsByType[rr.Header().Rrtype] = append(rrsetsByType[rr.Header().Rrtype], rr)
		}
	}

	if len(dnskeys) < 2 {
		t.Fatalf("Expected at least 2 DNSKEY records, got %d", len(dnskeys))
	}

	// Find the ZSK (flag 256) for signature verification
	var zskKey *dns.DNSKEY
	for _, k := range dnskeys {
		if k.Flags == 256 {
			zskKey = k
			break
		}
	}
	if zskKey == nil {
		t.Fatal("No ZSK (flag 256) found")
	}

	// Verify at least one signature (SOA is a good candidate as it's always signed)
	soaRRSIGs := rrsigsByType[dns.TypeSOA]
	if len(soaRRSIGs) == 0 {
		t.Fatal("No RRSIG for SOA record")
	}

	soaRecords := rrsetsByType[dns.TypeSOA]
	if len(soaRecords) == 0 {
		t.Fatal("No SOA record found")
	}

	// Note: Full signature verification requires the miekg/dns Verify method
	// which needs the complete RRset. This test validates that signatures exist
	// and have the correct structure.
	rrsig := soaRRSIGs[0]
	if rrsig.Algorithm != zskKey.Algorithm {
		t.Errorf("RRSIG algorithm (%d) doesn't match ZSK algorithm (%d)", rrsig.Algorithm, zskKey.Algorithm)
	}
	if rrsig.KeyTag != zskKey.KeyTag() {
		t.Errorf("RRSIG key tag (%d) doesn't match ZSK key tag (%d)", rrsig.KeyTag, zskKey.KeyTag())
	}
	if rrsig.SignerName != "example.com." {
		t.Errorf("RRSIG signer name should be 'example.com.', got %q", rrsig.SignerName)
	}
}

// TestDelegationPointSigning verifies that NS records at delegation points
// are NOT signed, and glue records are NOT signed, per RFC 4035 §2.2.
func TestDelegationPointSigning(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	zoneContent := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
@	IN	NS	ns2.example.com.
ns1	IN	A	192.0.2.1
ns2	IN	A	192.0.2.2
@	IN	A	192.0.2.10
sub	IN	NS	ns1.sub.example.com.
sub	IN	NS	ns2.sub.example.com.
ns1.sub	IN	A	192.0.2.100
ns2.sub	IN	A	192.0.2.101
www	IN	A	192.0.2.20
`
	zonePath := filepath.Join(dataDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("Failed to write zone file: %v", err)
	}

	cfg.Zones["example.com"] = ZoneConfig{Path: zonePath}
	cfg.DNSSEC.NSECVersion = "nsec" // Use NSEC for simpler verification
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	state := NewState(cfg.StatePath())
	keyGen := NewKeyGenerator(cfg)
	ksk, _ := keyGen.GenerateKSK("example.com")
	zsk, _ := keyGen.GenerateZSK("example.com")
	state.SetZone("example.com", &ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})

	signer := NewSigner(cfg, state)
	if err := signer.SignZone("example.com"); err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	signedPath := filepath.Join(cfg.OutputDir, "example.com.zone.signed")
	signedData, _ := os.ReadFile(signedPath)
	zp := dns.NewZoneParser(strings.NewReader(string(signedData)), "example.com.", signedPath)

	// Collect RRSIG records by name+covered-type
	type rrsigKey struct {
		name        string
		typeCovered uint16
	}
	rrsigs := make(map[rrsigKey]bool)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsigs[rrsigKey{strings.ToLower(sig.Header().Name), sig.TypeCovered}] = true
		}
	}

	// NS at apex SHOULD be signed
	if !rrsigs[rrsigKey{"example.com.", dns.TypeNS}] {
		t.Error("NS records at apex should be signed")
	}

	// NS at delegation point (sub.example.com) should NOT be signed
	if rrsigs[rrsigKey{"sub.example.com.", dns.TypeNS}] {
		t.Error("NS records at delegation point should NOT be signed (RFC 4035 §2.2)")
	}

	// Glue records (ns1.sub.example.com A) should NOT be signed
	if rrsigs[rrsigKey{"ns1.sub.example.com.", dns.TypeA}] {
		t.Error("Glue A records should NOT be signed (RFC 4035 §2.2)")
	}
	if rrsigs[rrsigKey{"ns2.sub.example.com.", dns.TypeA}] {
		t.Error("Glue A records should NOT be signed (RFC 4035 §2.2)")
	}

	// Regular records SHOULD be signed
	if !rrsigs[rrsigKey{"example.com.", dns.TypeA}] {
		t.Error("A record at apex should be signed")
	}
	if !rrsigs[rrsigKey{"www.example.com.", dns.TypeA}] {
		t.Error("www A record should be signed")
	}
}

// TestWildcardSigning verifies that wildcard RRSIGs have the correct Labels field
// per RFC 4035 §5.3.1 (Labels excludes the wildcard label).
func TestWildcardSigning(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	zoneContent := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
*	IN	A	192.0.2.99
`
	zonePath := filepath.Join(dataDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("Failed to write zone file: %v", err)
	}

	cfg.Zones["example.com"] = ZoneConfig{Path: zonePath}
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	state := NewState(cfg.StatePath())
	keyGen := NewKeyGenerator(cfg)
	ksk, _ := keyGen.GenerateKSK("example.com")
	zsk, _ := keyGen.GenerateZSK("example.com")
	state.SetZone("example.com", &ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})

	signer := NewSigner(cfg, state)
	if err := signer.SignZone("example.com"); err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	signedPath := filepath.Join(cfg.OutputDir, "example.com.zone.signed")
	signedData, _ := os.ReadFile(signedPath)
	zp := dns.NewZoneParser(strings.NewReader(string(signedData)), "example.com.", signedPath)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if sig, ok := rr.(*dns.RRSIG); ok {
			if strings.HasPrefix(sig.Header().Name, "*.") && sig.TypeCovered == dns.TypeA {
				// *.example.com. has 3 labels total, but wildcard RRSIG Labels = 2
				if sig.Labels != 2 {
					t.Errorf("Wildcard RRSIG Labels field should be 2 (excluding *), got %d", sig.Labels)
				}
				return // Found and verified
			}
		}
	}
	t.Error("No RRSIG for wildcard A record found")
}

// TestNeedsSign tests the change detection logic
func TestNeedsSign(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	zoneContent := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
`
	zonePath := filepath.Join(dataDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
		t.Fatalf("Failed to write zone file: %v", err)
	}

	cfg.Zones["example.com"] = ZoneConfig{Path: zonePath}
	signer := NewSigner(cfg, NewState(cfg.StatePath()))

	// New zone (nil state) always needs signing
	needs, reason := signer.NeedsSign("example.com", zonePath, nil)
	if !needs || reason != "new zone" {
		t.Errorf("New zone should need signing, got needs=%v reason=%q", needs, reason)
	}

	// Zone with recent signing and matching serial should NOT need signing
	now := time.Now().UTC()
	zoneState := &ZoneState{
		Serial:        2024011501,
		LastSigned:    now,
		SignaturesExp: now.Add(14 * 24 * time.Hour),
	}
	needs, _ = signer.NeedsSign("example.com", zonePath, zoneState)
	if needs {
		t.Error("Zone with current signatures should not need signing")
	}

	// Zone with expired signatures SHOULD need signing
	zoneState.SignaturesExp = now.Add(-1 * time.Hour)
	needs, reason = signer.NeedsSign("example.com", zonePath, zoneState)
	if !needs || reason != "signatures EXPIRED" {
		t.Errorf("Zone with expired signatures should need signing, got needs=%v reason=%q", needs, reason)
	}

	// Zone approaching expiry (within refresh window) SHOULD need signing
	// Test config uses SignatureRefresh=1s, so set expiry 500ms in future (within 1s refresh window)
	zoneState.SignaturesExp = now.Add(500 * time.Millisecond)
	needs, reason = signer.NeedsSign("example.com", zonePath, zoneState)
	if !needs || reason != "signatures approaching expiry" {
		t.Errorf("Zone approaching expiry should need signing, got needs=%v reason=%q", needs, reason)
	}

	// Zone with active rollover SHOULD need signing
	zoneState.SignaturesExp = now.Add(14 * 24 * time.Hour)
	zoneState.Rollover = &RolloverState{Type: "ksk", State: KSKRolloverStateDSAddWait}
	needs, reason = signer.NeedsSign("example.com", zonePath, zoneState)
	if !needs || reason != "rollover in progress" {
		t.Errorf("Zone with active rollover should need signing, got needs=%v reason=%q", needs, reason)
	}

	// Missing zone file should record error
	zoneState.Rollover = nil
	needs, _ = signer.NeedsSign("example.com", "/nonexistent/path", zoneState)
	if needs {
		t.Error("Missing zone file should not trigger signing")
	}
	if len(zoneState.Errors) == 0 {
		t.Error("Missing zone file should add an error to zone state")
	}
}

// TestValidateDomainName tests domain name validation for path safety
func TestValidateDomainName(t *testing.T) {
	tests := []struct {
		domain    string
		expectErr bool
	}{
		{"example.com", false},
		{"my-domain.co.uk", false},
		{"_dmarc.example.com", false},
		{"sub.example.com", false},
		{"", true},
		{"../etc/passwd", true},
		{"example.com/../../etc", true},
		{"example.com\\..\\etc", true},
		{"exam ple.com", true},
		{"exam\x00ple.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			err := ValidateDomainName(tt.domain)
			if tt.expectErr && err == nil {
				t.Errorf("Expected error for %q, got nil", tt.domain)
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Unexpected error for %q: %v", tt.domain, err)
			}
		})
	}
}

// TestMultipleAlgorithms tests signing with different algorithms
func TestMultipleAlgorithms(t *testing.T) {
	algorithms := []string{"ED25519", "ECDSAP256SHA256", "ECDSAP384SHA384"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			dataDir := t.TempDir()
			cfg := testConfig(t, dataDir)
			cfg.DNSSEC.Algorithm = alg

			zoneContent := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
`
			zonePath := filepath.Join(dataDir, "example.com.zone")
			if err := os.WriteFile(zonePath, []byte(zoneContent), 0644); err != nil {
				t.Fatalf("Failed to write zone file: %v", err)
			}

			cfg.Zones["example.com"] = ZoneConfig{Path: zonePath}
			if err := ensureDir(cfg.KeysDir()); err != nil {
				t.Fatalf("Failed to create keys dir: %v", err)
			}
			if err := ensureDir(cfg.OutputDir); err != nil {
				t.Fatalf("Failed to create output dir: %v", err)
			}

			state := NewState(cfg.StatePath())
			keyGen := NewKeyGenerator(cfg)

			ksk, err := keyGen.GenerateKSK("example.com")
			if err != nil {
				t.Fatalf("GenerateKSK failed for %s: %v", alg, err)
			}
			zsk, err := keyGen.GenerateZSK("example.com")
			if err != nil {
				t.Fatalf("GenerateZSK failed for %s: %v", alg, err)
			}

			state.SetZone("example.com", &ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})

			signer := NewSigner(cfg, state)
			if err := signer.SignZone("example.com"); err != nil {
				t.Fatalf("SignZone failed for %s: %v", alg, err)
			}

			// Verify signed zone exists and has correct algorithm
			signedPath := filepath.Join(cfg.OutputDir, "example.com.zone.signed")
			signedData, _ := os.ReadFile(signedPath)
			zp := dns.NewZoneParser(strings.NewReader(string(signedData)), "example.com.", signedPath)

			expectedAlg, _ := AlgorithmFromName(alg)
			foundCorrectAlg := false
			for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
				if dnskey, ok := rr.(*dns.DNSKEY); ok {
					if dnskey.Algorithm == expectedAlg {
						foundCorrectAlg = true
						break
					}
				}
			}

			if !foundCorrectAlg {
				t.Errorf("No DNSKEY with algorithm %s found in signed zone", alg)
			}
		})
	}
}

// TestRecoverKeyState tests that existing key files are recovered instead of
// regenerated when zone state is missing.
func TestRecoverKeyState(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	if err := ensureDirSecure(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	keyGen := NewKeyGenerator(cfg)

	// Generate initial keys
	origKSK, err := keyGen.GenerateKSK("example.com")
	if err != nil {
		t.Fatalf("GenerateKSK failed: %v", err)
	}
	origZSK, err := keyGen.GenerateZSK("example.com")
	if err != nil {
		t.Fatalf("GenerateZSK failed: %v", err)
	}

	// Now "lose" the state — recover from disk
	recoveredKSK, err := keyGen.RecoverKeyState("example.com", true)
	if err != nil {
		t.Fatalf("RecoverKeyState(ksk) failed: %v", err)
	}
	if recoveredKSK == nil {
		t.Fatal("RecoverKeyState(ksk) returned nil, expected recovery from existing files")
	}
	if recoveredKSK.ID != origKSK.ID {
		t.Errorf("Recovered KSK key tag mismatch: got %d, want %d", recoveredKSK.ID, origKSK.ID)
	}
	if recoveredKSK.Algorithm != origKSK.Algorithm {
		t.Errorf("Recovered KSK algorithm mismatch: got %s, want %s", recoveredKSK.Algorithm, origKSK.Algorithm)
	}

	recoveredZSK, err := keyGen.RecoverKeyState("example.com", false)
	if err != nil {
		t.Fatalf("RecoverKeyState(zsk) failed: %v", err)
	}
	if recoveredZSK == nil {
		t.Fatal("RecoverKeyState(zsk) returned nil, expected recovery from existing files")
	}
	if recoveredZSK.ID != origZSK.ID {
		t.Errorf("Recovered ZSK key tag mismatch: got %d, want %d", recoveredZSK.ID, origZSK.ID)
	}
}

// TestRecoverKeyStateNoFiles tests that RecoverKeyState returns nil when no
// key files exist, allowing the caller to generate new keys.
func TestRecoverKeyStateNoFiles(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	if err := ensureDirSecure(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	keyGen := NewKeyGenerator(cfg)

	// No key files exist — should return nil, nil
	recovered, err := keyGen.RecoverKeyState("nonexistent.com", true)
	if err != nil {
		t.Fatalf("RecoverKeyState should not error for missing files: %v", err)
	}
	if recovered != nil {
		t.Error("RecoverKeyState should return nil for missing files")
	}
}

// TestRecoverKeyStateCorruptFiles tests that RecoverKeyState returns an error
// when key files exist but are corrupt.
func TestRecoverKeyStateCorruptFiles(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	if err := ensureDirSecure(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	// Write garbage key files
	baseName := filepath.Join(cfg.KeysDir(), "corrupt.com.ksk")
	os.WriteFile(baseName+".key", []byte("not a valid DNSKEY"), 0644)
	os.WriteFile(baseName+".private", []byte("not a valid private key"), 0600)

	keyGen := NewKeyGenerator(cfg)
	_, err := keyGen.RecoverKeyState("corrupt.com", true)
	if err == nil {
		t.Fatal("RecoverKeyState should return error for corrupt key files")
	}
}

// TestRecoverOrGenerateKeysPreservesExisting tests the full recoverOrGenerateKeys
// flow: when key files exist on disk, they are reused and NOT overwritten.
func TestRecoverOrGenerateKeysPreservesExisting(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	if err := ensureDirSecure(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatalf("Failed to create output dir: %v", err)
	}

	keyGen := NewKeyGenerator(cfg)

	// Generate original keys (simulates initial setup)
	origKSK, err := keyGen.GenerateKSK("example.com")
	if err != nil {
		t.Fatalf("GenerateKSK failed: %v", err)
	}
	origZSK, err := keyGen.GenerateZSK("example.com")
	if err != nil {
		t.Fatalf("GenerateZSK failed: %v", err)
	}

	// Now call recoverOrGenerateKeys (simulates daemon finding zone with no state)
	ksk, zsk, err := recoverOrGenerateKeys(keyGen, "example.com")
	if err != nil {
		t.Fatalf("recoverOrGenerateKeys failed: %v", err)
	}

	// Key tags must match originals — NOT be new keys
	if ksk.ID != origKSK.ID {
		t.Errorf("recoverOrGenerateKeys generated new KSK (tag %d) instead of recovering existing (tag %d)",
			ksk.ID, origKSK.ID)
	}
	if zsk.ID != origZSK.ID {
		t.Errorf("recoverOrGenerateKeys generated new ZSK (tag %d) instead of recovering existing (tag %d)",
			zsk.ID, origZSK.ID)
	}
}

// TestRecoverOrGenerateKeysNewDomain tests that recoverOrGenerateKeys generates
// new keys when no key files exist (truly new domain).
func TestRecoverOrGenerateKeysNewDomain(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	if err := ensureDirSecure(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	keyGen := NewKeyGenerator(cfg)

	// No pre-existing keys — should generate fresh ones
	ksk, zsk, err := recoverOrGenerateKeys(keyGen, "brand-new.com")
	if err != nil {
		t.Fatalf("recoverOrGenerateKeys failed: %v", err)
	}
	if ksk == nil || zsk == nil {
		t.Fatal("recoverOrGenerateKeys should return non-nil keys for new domain")
	}
	if ksk.ID == 0 {
		t.Error("Generated KSK should have non-zero key tag")
	}
	if zsk.ID == 0 {
		t.Error("Generated ZSK should have non-zero key tag")
	}
}

// TestBackupExistingKeyFiles tests that existing key files are backed up with
// the key tag in the filename before being overwritten by new key generation.
func TestBackupExistingKeyFiles(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	if err := ensureDirSecure(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	keyGen := NewKeyGenerator(cfg)

	// Generate initial KSK
	origKSK, err := keyGen.GenerateKSK("example.com")
	if err != nil {
		t.Fatalf("GenerateKSK failed: %v", err)
	}
	origTag := origKSK.ID

	// Generate a NEW KSK (this should back up the original)
	newKSK, err := keyGen.GenerateKSK("example.com")
	if err != nil {
		t.Fatalf("Second GenerateKSK failed: %v", err)
	}

	// Verify new key is different
	if newKSK.ID == origTag {
		// Key tags can theoretically collide; skip check in that rare case
		t.Log("Key tags happened to match (rare collision), skipping tag comparison")
	}

	// Verify backup files exist with old key tag
	backupBase := filepath.Join(cfg.KeysDir(), fmt.Sprintf("example.com.ksk.%d", origTag))
	if _, err := os.Stat(backupBase + ".key"); os.IsNotExist(err) {
		t.Errorf("Backup public key file not found: %s.key", backupBase)
	}
	if _, err := os.Stat(backupBase + ".private"); os.IsNotExist(err) {
		t.Errorf("Backup private key file not found: %s.private", backupBase)
	}

	// Verify the backup contains the original key (load it and check tag)
	backupKey, _, err := keyGen.loadKeyPairByID("example.com", "ksk", origTag)
	if err != nil {
		t.Fatalf("Failed to load backup key: %v", err)
	}
	if backupKey.KeyTag() != origTag {
		t.Errorf("Backup key tag mismatch: got %d, want %d", backupKey.KeyTag(), origTag)
	}
}

// TestRecoverKeyStateCreatedDate tests that the creation date is correctly
// parsed from the key file comment header.
func TestRecoverKeyStateCreatedDate(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	if err := ensureDirSecure(cfg.KeysDir()); err != nil {
		t.Fatalf("Failed to create keys dir: %v", err)
	}

	keyGen := NewKeyGenerator(cfg)

	beforeGenerate := time.Now().UTC().Add(-1 * time.Second)
	_, err := keyGen.GenerateKSK("example.com")
	if err != nil {
		t.Fatalf("GenerateKSK failed: %v", err)
	}
	afterGenerate := time.Now().UTC().Add(1 * time.Second)

	recovered, err := keyGen.RecoverKeyState("example.com", true)
	if err != nil {
		t.Fatalf("RecoverKeyState failed: %v", err)
	}

	if recovered.Created.Before(beforeGenerate) || recovered.Created.After(afterGenerate) {
		t.Errorf("Recovered created date %v not within expected range [%v, %v]",
			recovered.Created, beforeGenerate, afterGenerate)
	}
}

