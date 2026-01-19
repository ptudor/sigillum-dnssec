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
	return kg.generateKey(domain, true)
}

// GenerateZSK generates a new Zone Signing Key
func (kg *KeyGenerator) GenerateZSK(domain string) (*KeyState, error) {
	return kg.generateKey(domain, false)
}

func (kg *KeyGenerator) generateKey(domain string, isKSK bool) (*KeyState, error) {
	algorithm := kg.cfg.DNSSEC.Algorithm

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

	slog.Info("Generating key", "domain", domain, "type", keyType, "algorithm", algorithm)

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
		// Public key for P-256: X || Y (32 bytes each)
		pubBytes := append(privKey.PublicKey.X.Bytes(), privKey.PublicKey.Y.Bytes()...)
		dnskey.PublicKey = base64.StdEncoding.EncodeToString(pubBytes)
		privateKey = privKey.D.Bytes()

	case "ECDSAP384SHA384":
		dnskey.Algorithm = dns.ECDSAP384SHA384
		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generating ECDSA P-384 key: %w", err)
		}
		// Public key for P-384: X || Y (48 bytes each)
		pubBytes := append(privKey.PublicKey.X.Bytes(), privKey.PublicKey.Y.Bytes()...)
		dnskey.PublicKey = base64.StdEncoding.EncodeToString(pubBytes)
		privateKey = privKey.D.Bytes()

	default:
		return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	return dnskey, privateKey, nil
}

func (kg *KeyGenerator) saveKeyFiles(domain, keyType string, dnskey *dns.DNSKEY, privateKey []byte) error {
	keysDir := kg.cfg.KeysDir()
	if err := ensureDir(keysDir); err != nil {
		return err
	}

	baseName := filepath.Join(keysDir, fmt.Sprintf("%s.%s", domain, keyType))

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

	slog.Debug("Saved key files", "domain", domain, "type", keyType, "key_tag", dnskey.KeyTag())
	return nil
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
	var lines []string
	var current string
	for _, c := range content {
		if c == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
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

// AlgorithmFromName returns the algorithm number from name
func AlgorithmFromName(name string) uint8 {
	names := map[string]uint8{
		"ED25519":         dns.ED25519,
		"ECDSAP256SHA256": dns.ECDSAP256SHA256,
		"ECDSAP384SHA384": dns.ECDSAP384SHA384,
		"RSASHA256":       dns.RSASHA256,
		"RSASHA512":       dns.RSASHA512,
	}
	return names[name]
}

// ensureDir creates a directory if it doesn't exist
func ensureDir(path string) error {
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("creating directory %s: %w", path, err)
	}
	return nil
}
