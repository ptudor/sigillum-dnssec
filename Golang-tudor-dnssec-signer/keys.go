package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// KeyGenerator handles DNSSEC key generation and storage
type KeyGenerator struct {
	cfg *Config
}

// NewKeyGenerator creates a new key generator
func NewKeyGenerator(cfg *Config) *KeyGenerator {
	return &KeyGenerator{cfg: cfg}
}

// GenerateKSK generates a new Key Signing Key
func (kg *KeyGenerator) GenerateKSK(domain string) (*KeyState, error) {
	return kg.generateKey(domain, true, "")
}

// GenerateZSK generates a new Zone Signing Key
func (kg *KeyGenerator) GenerateZSK(domain string) (*KeyState, error) {
	return kg.generateKey(domain, false, "")
}

// GenerateKSKWithAlgorithm generates a new Key Signing Key with a specific algorithm
func (kg *KeyGenerator) GenerateKSKWithAlgorithm(domain, algorithm string) (*KeyState, error) {
	return kg.generateKey(domain, true, algorithm)
}

// GenerateZSKWithAlgorithm generates a new Zone Signing Key with a specific algorithm
func (kg *KeyGenerator) GenerateZSKWithAlgorithm(domain, algorithm string) (*KeyState, error) {
	return kg.generateKey(domain, false, algorithm)
}

func (kg *KeyGenerator) generateKey(domain string, isKSK bool, algorithmOverride string) (*KeyState, error) {
	algorithm := algorithmOverride
	if algorithm == "" {
		algorithm = kg.cfg.GetZoneAlgorithm(domain)
	}

	var lifetime time.Duration
	var keyType string
	var flags uint16
	if isKSK {
		lifetime = kg.cfg.GetZoneKSKLifetime(domain)
		keyType = "ksk"
		flags = 257 // KSK flag
	} else {
		lifetime = kg.cfg.GetZoneZSKLifetime(domain)
		keyType = "zsk"
		flags = 256 // ZSK flag
	}

	slog.Info("[KEY] Generating key", "domain", domain, "type", keyType, "algorithm", algorithm)

	// Generate the key pair
	dnskey, privateKey, err := generateDNSSECKey(domain, algorithm, flags)
	if err != nil {
		return nil, fmt.Errorf("generating %s: %w", keyType, err)
	}

	// Compute key tag
	keyTag := dnskey.KeyTag()

	// Save key files
	if err := kg.saveKeyFiles(domain, keyType, dnskey, privateKey); err != nil {
		return nil, fmt.Errorf("saving key files: %w", err)
	}

	now := time.Now().UTC()
	return &KeyState{
		ID:          keyTag,
		Algorithm:   algorithm,
		Created:     now,
		Expires:     now.Add(lifetime),
		RolloverDue: now.Add(time.Duration(float64(lifetime) * 0.75)), // 75% of lifetime
	}, nil
}

// generateDNSSECKey generates a DNSKEY and corresponding private key
func generateDNSSECKey(domain, algorithm string, flags uint16) (*dns.DNSKEY, []byte, error) {
	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Flags:    flags,
		Protocol: 3, // DNSSEC
	}

	var privateKey []byte

	switch algorithm {
	case "ED25519":
		dnskey.Algorithm = dns.ED25519
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating ED25519 key: %w", err)
		}
		dnskey.PublicKey = base64.StdEncoding.EncodeToString(pub)
		privateKey = priv

	case "ECDSAP256SHA256":
		dnskey.Algorithm = dns.ECDSAP256SHA256
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating ECDSA P-256 key: %w", err)
		}
		// Public key for P-256: X || Y (32 bytes each, zero-padded)
		pubBytes := make([]byte, 64)
		privKey.PublicKey.X.FillBytes(pubBytes[:32])
		privKey.PublicKey.Y.FillBytes(pubBytes[32:])
		dnskey.PublicKey = base64.StdEncoding.EncodeToString(pubBytes)
		// Private key D also needs zero-padding
		privateKey = make([]byte, 32)
		privKey.D.FillBytes(privateKey)

	case "ECDSAP384SHA384":
		dnskey.Algorithm = dns.ECDSAP384SHA384
		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating ECDSA P-384 key: %w", err)
		}
		// Public key for P-384: X || Y (48 bytes each, zero-padded)
		pubBytes := make([]byte, 96)
		privKey.PublicKey.X.FillBytes(pubBytes[:48])
		privKey.PublicKey.Y.FillBytes(pubBytes[48:])
		dnskey.PublicKey = base64.StdEncoding.EncodeToString(pubBytes)
		// Private key D also needs zero-padding
		privateKey = make([]byte, 48)
		privKey.D.FillBytes(privateKey)

	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return dnskey, privateKey, nil
}

func (kg *KeyGenerator) saveKeyFiles(domain, keyType string, dnskey *dns.DNSKEY, privateKey []byte) error {
	keysDir := kg.cfg.KeysDir()
	if err := ensureDirSecure(keysDir); err != nil {
		return err
	}

	baseName := filepath.Join(keysDir, fmt.Sprintf("%s.%s", domain, keyType))

	// Back up existing key files before overwriting to prevent silent key
	// material loss. If we're about to overwrite a KSK whose key tag matches
	// a DS record at the registrar, the backup is the only way to recover.
	kg.backupExistingKeyFiles(domain, keyType, baseName)

	// Write public key file (.key) in BIND format
	keyFile := baseName + ".key"
	keyContent := fmt.Sprintf("; Key tag: %d\n; Algorithm: %s\n; Created: %s\n%s\n",
		dnskey.KeyTag(),
		AlgorithmName(dnskey.Algorithm),
		time.Now().UTC().Format(time.RFC3339),
		dnskey.String())

	if err := os.WriteFile(keyFile, []byte(keyContent), 0644); err != nil {
		return fmt.Errorf("writing public key file: %w", err)
	}

	// Write private key file (.private)
	privFile := baseName + ".private"
	privContent := formatPrivateKey(dnskey, privateKey)

	if err := os.WriteFile(privFile, []byte(privContent), 0600); err != nil {
		return fmt.Errorf("writing private key file: %w", err)
	}

	slog.Debug("[KEY] Saved key files", "domain", domain, "type", keyType, "key_tag", dnskey.KeyTag())
	return nil
}

// backupExistingKeyFiles checks for pre-existing key files and backs them up
// with the key tag in the filename (matching rollover's backup convention)
// before they are overwritten by new key generation.
func (kg *KeyGenerator) backupExistingKeyFiles(domain, keyType, baseName string) {
	keyFile := baseName + ".key"
	privFile := baseName + ".private"

	// Check if key file exists
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return // No existing key file, nothing to back up
	}

	// Parse existing DNSKEY to get its key tag for the backup filename
	existingKey, err := parseDNSKEYFromFile(string(keyData))
	if err != nil {
		slog.Warn("[KEY] Cannot parse existing key file for backup, renaming with .bak",
			"domain", domain, "type", keyType, "error", err)
		// Fall back to .bak suffix
		os.Rename(keyFile, keyFile+".bak")
		os.Rename(privFile, privFile+".bak")
		return
	}

	existingTag := existingKey.KeyTag()
	keysDir := kg.cfg.KeysDir()
	backupBase := filepath.Join(keysDir, fmt.Sprintf("%s.%s.%d", domain, keyType, existingTag))

	// Don't overwrite an existing backup (from a prior rollover)
	if _, err := os.Stat(backupBase + ".key"); err == nil {
		slog.Debug("[KEY] Backup already exists, skipping",
			"domain", domain, "type", keyType, "key_tag", existingTag)
		return
	}

	if err := os.Rename(keyFile, backupBase+".key"); err != nil {
		slog.Warn("[KEY] Failed to back up public key file",
			"domain", domain, "type", keyType, "error", err)
		return
	}
	if err := os.Rename(privFile, backupBase+".private"); err != nil {
		slog.Warn("[KEY] Failed to back up private key file",
			"domain", domain, "type", keyType, "error", err)
		// Try to restore the public key rename
		os.Rename(backupBase+".key", keyFile)
		return
	}

	slog.Warn("[KEY] Backed up existing key files before overwrite",
		"domain", domain, "type", keyType, "old_key_tag", existingTag,
		"backup", backupBase)
}

// formatPrivateKey formats a private key in BIND-compatible format
func formatPrivateKey(dnskey *dns.DNSKEY, privateKey []byte) string {
	return fmt.Sprintf(`Private-key-format: v1.3
Algorithm: %d (%s)
PrivateKey: %s
Created: %s
`,
		dnskey.Algorithm,
		AlgorithmName(dnskey.Algorithm),
		base64.StdEncoding.EncodeToString(privateKey),
		time.Now().UTC().Format("20060102150405"))
}

// RecoverKeyState attempts to load an existing key pair from disk and reconstruct
// a KeyState from it. This is used when a zone has no state entry but key files
// already exist on disk — recovering the existing keys preserves the DS chain of
// trust instead of generating new keys that would cause a SERVFAIL.
//
// Returns nil (no error) if key files don't exist — the caller should generate
// new keys in that case. Returns an error only if files exist but are corrupt.
func (kg *KeyGenerator) RecoverKeyState(domain string, isKSK bool) (*KeyState, error) {
	var keyType string
	var lifetime time.Duration
	if isKSK {
		keyType = "ksk"
		lifetime = kg.cfg.GetZoneKSKLifetime(domain)
	} else {
		keyType = "zsk"
		lifetime = kg.cfg.GetZoneZSKLifetime(domain)
	}

	keysDir := kg.cfg.KeysDir()
	baseName := filepath.Join(keysDir, fmt.Sprintf("%s.%s", domain, keyType))
	keyFile := baseName + ".key"
	privFile := baseName + ".private"

	// Check if both key files exist
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return nil, nil // No key files, caller should generate
	}
	if _, err := os.Stat(privFile); os.IsNotExist(err) {
		return nil, nil // Missing private key, caller should generate
	}

	// Try to load and validate the key pair
	dnskey, _, err := kg.loadKeyPairFromPath(baseName)
	if err != nil {
		return nil, fmt.Errorf("existing %s key files are corrupt: %w", keyType, err)
	}

	keyTag := dnskey.KeyTag()

	// Parse creation date from key file comments ("; Created: <RFC3339>")
	created := kg.parseKeyFileCreatedDate(keyFile)

	// Reconstruct KeyState with recovered metadata
	state := &KeyState{
		ID:          keyTag,
		Algorithm:   AlgorithmName(dnskey.Algorithm),
		Created:     created,
		Expires:     created.Add(lifetime),
		RolloverDue: created.Add(time.Duration(float64(lifetime) * 0.75)),
	}

	slog.Warn("[KEY] Recovered existing key from disk (state was missing)",
		"domain", domain, "type", keyType, "key_tag", keyTag,
		"algorithm", state.Algorithm, "created", created.Format(time.RFC3339))

	return state, nil
}

// parseKeyFileCreatedDate extracts the creation timestamp from a key file's
// comment header. Returns the file's mtime as fallback if parsing fails.
func (kg *KeyGenerator) parseKeyFileCreatedDate(keyFile string) time.Time {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return kg.keyFileMtime(keyFile)
	}

	for _, line := range splitLines(string(data)) {
		if strings.HasPrefix(line, "; Created: ") {
			dateStr := strings.TrimPrefix(line, "; Created: ")
			if t, err := time.Parse(time.RFC3339, dateStr); err == nil {
				return t
			}
		}
	}

	return kg.keyFileMtime(keyFile)
}

// keyFileMtime returns a file's modification time, or time.Now() as last resort.
func (kg *KeyGenerator) keyFileMtime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Now().UTC()
	}
	return info.ModTime().UTC()
}

// recoverOrGenerateKeys attempts to recover existing key files from disk before
// falling back to generating new keys. This prevents DS chain of trust breakage
// when a zone's state entry is lost but key files still exist on disk.
func recoverOrGenerateKeys(keyGen *KeyGenerator, domain string) (ksk *KeyState, zsk *KeyState, err error) {
	// Try to recover KSK from disk
	ksk, err = keyGen.RecoverKeyState(domain, true)
	if err != nil {
		slog.Error("[KEY] Existing KSK files are corrupt, generating new KSK",
			"domain", domain, "error", err)
		ksk = nil
	}
	if ksk == nil {
		ksk, err = keyGen.GenerateKSK(domain)
		if err != nil {
			return nil, nil, fmt.Errorf("generating KSK for %s: %w", domain, err)
		}
	}

	// Try to recover ZSK from disk
	zsk, err = keyGen.RecoverKeyState(domain, false)
	if err != nil {
		slog.Error("[KEY] Existing ZSK files are corrupt, generating new ZSK",
			"domain", domain, "error", err)
		zsk = nil
	}
	if zsk == nil {
		zsk, err = keyGen.GenerateZSK(domain)
		if err != nil {
			return nil, nil, fmt.Errorf("generating ZSK for %s: %w", domain, err)
		}
	}

	return ksk, zsk, nil
}

// LoadKeyPair loads a key pair from disk
func (kg *KeyGenerator) LoadKeyPair(domain, keyType string) (*dns.DNSKEY, []byte, error) {
	keysDir := kg.cfg.KeysDir()
	baseName := filepath.Join(keysDir, fmt.Sprintf("%s.%s", domain, keyType))
	return kg.loadKeyPairFromPath(baseName)
}

// loadKeyPairByID loads a backup key pair by its key ID
func (kg *KeyGenerator) loadKeyPairByID(domain, keyType string, keyID uint16) (*dns.DNSKEY, []byte, error) {
	keysDir := kg.cfg.KeysDir()
	baseName := filepath.Join(keysDir, fmt.Sprintf("%s.%s.%d", domain, keyType, keyID))
	return kg.loadKeyPairFromPath(baseName)
}

// loadKeyPairFromPath loads a key pair from the given base path
func (kg *KeyGenerator) loadKeyPairFromPath(baseName string) (*dns.DNSKEY, []byte, error) {
	// Read public key
	keyFile := baseName + ".key"
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading public key: %w", err)
	}

	// Parse DNSKEY from file
	dnskey, err := parseDNSKEYFromFile(string(keyData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing public key: %w", err)
	}

	// Read private key
	privFile := baseName + ".private"
	privData, err := os.ReadFile(privFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading private key: %w", err)
	}

	privateKey, err := parsePrivateKeyFromFile(string(privData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing private key: %w", err)
	}

	return dnskey, privateKey, nil
}

// parseDNSKEYFromFile parses a DNSKEY record from a key file
func parseDNSKEYFromFile(content string) (*dns.DNSKEY, error) {
	for _, line := range splitLines(content) {
		if len(line) == 0 || line[0] == ';' {
			continue
		}
		rr, err := dns.NewRR(line)
		if err != nil {
			continue
		}
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			return dnskey, nil
		}
	}
	return nil, fmt.Errorf("no DNSKEY record found in file")
}

// parsePrivateKeyFromFile parses a private key from BIND format
func parsePrivateKeyFromFile(content string) ([]byte, error) {
	for _, line := range splitLines(content) {
		if len(line) > 12 && line[:12] == "PrivateKey: " {
			return base64.StdEncoding.DecodeString(line[12:])
		}
	}
	return nil, fmt.Errorf("no PrivateKey field found in file")
}

// splitLines splits content into lines
func splitLines(content string) []string {
	return strings.Split(content, "\n")
}

// AlgorithmName returns the name of a DNSSEC algorithm
func AlgorithmName(alg uint8) string {
	names := map[uint8]string{
		dns.RSAMD5:           "RSAMD5",
		dns.DH:               "DH",
		dns.DSA:              "DSA",
		dns.RSASHA1:          "RSASHA1",
		dns.DSANSEC3SHA1:     "DSA-NSEC3-SHA1",
		dns.RSASHA1NSEC3SHA1: "RSASHA1-NSEC3-SHA1",
		dns.RSASHA256:        "RSASHA256",
		dns.RSASHA512:        "RSASHA512",
		dns.ECCGOST:          "ECC-GOST",
		dns.ECDSAP256SHA256:  "ECDSAP256SHA256",
		dns.ECDSAP384SHA384:  "ECDSAP384SHA384",
		dns.ED25519:          "ED25519",
		dns.ED448:            "ED448",
	}
	if name, ok := names[alg]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", alg)
}

// AlgorithmFromName returns the algorithm number from name.
// Returns an error if the algorithm name is not recognized.
func AlgorithmFromName(name string) (uint8, error) {
	names := map[string]uint8{
		"ED25519":         dns.ED25519,
		"ECDSAP256SHA256": dns.ECDSAP256SHA256,
		"ECDSAP384SHA384": dns.ECDSAP384SHA384,
		"RSASHA256":       dns.RSASHA256,
		"RSASHA512":       dns.RSASHA512,
	}
	alg, ok := names[name]
	if !ok {
		return 0, fmt.Errorf("unknown algorithm: %q", name)
	}
	return alg, nil
}

// ensureDir creates a directory if it doesn't exist
func ensureDir(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", path, err)
	}
	return nil
}

// ensureDirSecure creates a directory with 0700 permissions if it doesn't exist,
// and tightens permissions if it already exists with wider access.
func ensureDirSecure(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("creating directory %s: %w", path, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", path)
	}
	// Tighten permissions if too open
	perm := info.Mode().Perm()
	if perm&0077 != 0 {
		slog.Warn("[SECURITY] Tightening directory permissions", "path", path, "old", fmt.Sprintf("%04o", perm), "new", "0700")
		if err := os.Chmod(path, 0700); err != nil {
			return fmt.Errorf("chmod %s: %w", path, err)
		}
	}
	return nil
}
