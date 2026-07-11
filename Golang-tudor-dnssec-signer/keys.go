package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
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

	// Regenerate on a key-tag collision (bounded). A 16-bit key tag is not unique
	// (RFC 4034 App. B); a collision with the zone's current keys or a backed-up
	// key would corrupt rollover identity (OldKeyID == NewKeyID), clobber a
	// backup file named by tag, and make Dynadot's upsert-by-key_tag replace the
	// old DS instead of adding — so mint a fresh key until the tag is unused
	// (R-029). ~1/65536 per generation, so this loop almost never iterates.
	existingTags := kg.existingKeyTags(domain)
	const maxTagAttempts = 10
	var dnskey *dns.DNSKEY
	var privateKey []byte
	var keyTag uint16
	for attempt := 1; ; attempt++ {
		var err error
		dnskey, privateKey, err = generateDNSSECKey(domain, algorithm, flags)
		if err != nil {
			return nil, fmt.Errorf("generating %s: %w", keyType, err)
		}
		keyTag = dnskey.KeyTag()
		if !tagInUse(keyTag, existingTags) {
			break
		}
		if attempt >= maxTagAttempts {
			slog.Warn("[KEY] key tag still collides after retries; proceeding",
				"domain", domain, "type", keyType, "tag", keyTag, "attempts", attempt)
			break
		}
		slog.Debug("[KEY] regenerating on key-tag collision",
			"domain", domain, "type", keyType, "tag", keyTag, "attempt", attempt)
	}

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

// tagInUse reports whether keyTag collides with a tag already used by the zone.
// Pure so it can be unit-tested (R-029); the set is built by existingKeyTags.
func tagInUse(keyTag uint16, existingTags map[uint16]bool) bool {
	return existingTags[keyTag]
}

// existingKeyTags collects every key tag currently in use for a domain: the tags
// of its live KSK/ZSK plus the tags of every backed-up key file. Rollover backs
// up old keys as <domain>.<type>.<tag>.key (the numeric field IS the key tag,
// since KeyState.ID == keytag), so scanning those filenames also covers an
// in-progress rollover's old key. A read/parse failure just yields fewer known
// tags (collision avoidance is best-effort, never fatal).
func (kg *KeyGenerator) existingKeyTags(domain string) map[uint16]bool {
	tags := make(map[uint16]bool)
	dir := kg.cfg.KeysDir()

	// Backup files: <domain>.<ksk|zsk>.<tag>.key
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".key") {
				continue
			}
			for _, kt := range []string{"ksk", "zsk"} {
				prefix := domain + "." + kt + "."
				if !strings.HasPrefix(name, prefix) {
					continue
				}
				mid := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".key")
				if n, err := strconv.ParseUint(mid, 10, 16); err == nil {
					tags[uint16(n)] = true
				}
			}
		}
	}

	// Current live keys (not tag-named): parse them for their tags.
	for _, kt := range []string{"ksk", "zsk"} {
		if dk, err := kg.loadPublicKeyFromPath(filepath.Join(dir, domain+"."+kt)); err == nil {
			tags[dk.KeyTag()] = true
		}
	}

	return tags
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

	// Back up existing key files before overwriting to prevent silent key material loss.
	// If we're about to overwrite a KSK whose key tag matches a DS record at the
	// registrar, the backup is the only way to recover — so a backup failure now ABORTS
	// (R-027), leaving the live pair untouched rather than destroying the only copy.
	if err := kg.backupExistingKeyFiles(domain, keyType, baseName); err != nil {
		return fmt.Errorf("backing up existing %s key before overwrite: %w", keyType, err)
	}

	keyFile := baseName + ".key"
	keyContent := fmt.Sprintf("; Key tag: %d\n; Algorithm: %s\n; Created: %s\n%s\n",
		dnskey.KeyTag(),
		AlgorithmName(dnskey.Algorithm),
		time.Now().UTC().Format(time.RFC3339),
		dnskey.String())
	privFile := baseName + ".private"
	privContent := formatPrivateKey(dnskey, privateKey)

	// Write each half atomically (temp + fsync + rename) so a crash can never leave a
	// truncated key file or pair a new .key with an old .private (R-009). Write .private
	// first: if a crash lands between the two, the correspondence check in
	// loadKeyPairFromPath rejects the resulting pair and the prior signed zone keeps
	// serving, rather than a half-written file being read.
	if err := writeFileAtomicOwned(privFile, []byte(privContent), 0600); err != nil {
		return fmt.Errorf("writing private key file: %w", err)
	}
	if err := writeFileAtomicOwned(keyFile, []byte(keyContent), 0644); err != nil {
		return fmt.Errorf("writing public key file: %w", err)
	}

	slog.Debug("[KEY] Saved key files", "domain", domain, "type", keyType, "key_tag", dnskey.KeyTag())
	return nil
}

// backupExistingKeyFiles checks for pre-existing key files and backs them up with the key
// tag in the filename (matching rollover's backup convention) before they are overwritten
// by new key generation. It returns an error on any backup failure so the caller can abort
// the overwrite and leave the live pair intact (R-027) — the backup is the only copy of a
// KSK whose DS is at the registrar.
func (kg *KeyGenerator) backupExistingKeyFiles(domain, keyType, baseName string) error {
	keyFile := baseName + ".key"
	privFile := baseName + ".private"

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No existing key file, nothing to back up.
		}
		return fmt.Errorf("reading existing key file: %w", err)
	}

	// Parse existing DNSKEY to get its key tag for the backup filename.
	existingKey, err := parseDNSKEYFromFile(string(keyData))
	if err != nil {
		// Unparseable existing key: preserve it under a UNIQUE .bak base so a prior
		// .bak from an earlier failure is never clobbered.
		slog.Warn("[KEY] Cannot parse existing key file for backup; preserving under a unique .bak",
			"domain", domain, "type", keyType, "error", err)
		bakBase, err := uniqueBackupBase(baseName + ".bak")
		if err != nil {
			return err
		}
		return moveKeyPair(keyFile, privFile, bakBase)
	}

	existingTag := existingKey.KeyTag()
	keysDir := kg.cfg.KeysDir()
	backupBase := filepath.Join(keysDir, fmt.Sprintf("%s.%s.%d", domain, keyType, existingTag))

	// A backup at the tag-named slot may already exist (from a prior rollover). Only skip
	// when it holds the SAME key — a key-tag collision could otherwise let us silently
	// drop a different key's backup. If it differs, preserve the live key under a unique
	// name instead of overwriting the existing backup.
	if fileExists(backupBase + ".key") {
		if existingBackup, err := kg.loadPublicKeyFromPath(backupBase); err == nil &&
			existingBackup.PublicKey == existingKey.PublicKey {
			slog.Debug("[KEY] Backup already exists (same key), skipping",
				"domain", domain, "type", keyType, "key_tag", existingTag)
			return nil
		}
		slog.Warn("[KEY] Tag-named backup exists but holds a different key; using a unique backup name",
			"domain", domain, "type", keyType, "key_tag", existingTag)
		uniq, err := uniqueBackupBase(backupBase)
		if err != nil {
			return err
		}
		return moveKeyPair(keyFile, privFile, uniq)
	}

	if err := moveKeyPair(keyFile, privFile, backupBase); err != nil {
		return err
	}
	slog.Warn("[KEY] Backed up existing key files before overwrite",
		"domain", domain, "type", keyType, "old_key_tag", existingTag,
		"backup", backupBase)
	return nil
}

// moveKeyPair renames a .key/.private pair to a new base, restoring the .key rename if the
// .private rename fails so the live pair is never left split.
func moveKeyPair(keyFile, privFile, destBase string) error {
	if err := os.Rename(keyFile, destBase+".key"); err != nil {
		return fmt.Errorf("backing up public key file: %w", err)
	}
	if fileExists(privFile) {
		if err := os.Rename(privFile, destBase+".private"); err != nil {
			os.Rename(destBase+".key", keyFile) // undo, keep the live pair together
			return fmt.Errorf("backing up private key file: %w", err)
		}
	}
	return nil
}

// uniqueBackupBase returns a base path derived from prefix that has neither a .key nor a
// .private file yet, so a backup pair can be written without clobbering an existing one.
func uniqueBackupBase(prefix string) (string, error) {
	for i := 0; i < 10000; i++ {
		candidate := fmt.Sprintf("%s.%d", prefix, i)
		if !fileExists(candidate+".key") && !fileExists(candidate+".private") {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("could not allocate a unique backup path for %s", prefix)
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

	// Return "caller should generate" ONLY when both halves are absent (a genuinely new
	// domain). When exactly one half exists — the artifact of the R-009 crash window or a
	// botched restore — refuse: regenerating would mint a brand-new KSK while the parent
	// DS still matches the surviving on-disk .key, silently breaking the chain (R-028).
	keyExists, err := statExists(keyFile)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", keyFile, err)
	}
	privExists, err := statExists(privFile)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", privFile, err)
	}
	if !keyExists && !privExists {
		return nil, nil // No key files, caller should generate.
	}
	if keyExists != privExists {
		present, missing := keyFile, privFile
		if !keyExists {
			present, missing = privFile, keyFile
		}
		return nil, fmt.Errorf("incomplete %s key pair: %s exists but %s is missing; refusing to regenerate (restore the missing half, or remove the zone and re-add to mint fresh keys)", keyType, present, missing)
	}

	// Try to load and validate the key pair. A read failure here (e.g.
	// permission denied from a root-owned file) is reported as "cannot
	// read" rather than "corrupt" — callers decide whether to regenerate
	// based on the error type, and misclassifying permission issues as
	// corruption previously led to silent KSK regeneration.
	dnskey, _, err := kg.loadKeyPairFromPath(baseName)
	if err != nil {
		return nil, fmt.Errorf("cannot read existing %s key files: %w", keyType, err)
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
//
// If the key files exist but cannot be read or parsed, this function now
// returns an error rather than regenerating — silently minting a new KSK
// over an unreadable existing one breaks the DS chain at the registrar and
// causes SERVFAIL until the operator notices. Regeneration is reserved for
// the "no key files present" case only. An operator who truly wants new
// keys should `dnssec-tudor remove <domain>` + re-add.
func recoverOrGenerateKeys(keyGen *KeyGenerator, domain string) (ksk *KeyState, zsk *KeyState, err error) {
	ksk, err = keyGen.RecoverKeyState(domain, true)
	if err != nil {
		slog.Error("[KEY] Existing KSK files present but unreadable; refusing to regenerate",
			"domain", domain, "error", err,
			"hint", "check file permissions / ownership, or remove the zone and re-add to mint fresh keys")
		return nil, nil, fmt.Errorf("KSK recovery failed for %s (refusing to regenerate): %w", domain, err)
	}
	if ksk == nil {
		ksk, err = keyGen.GenerateKSK(domain)
		if err != nil {
			return nil, nil, fmt.Errorf("generating KSK for %s: %w", domain, err)
		}
	}

	zsk, err = keyGen.RecoverKeyState(domain, false)
	if err != nil {
		slog.Error("[KEY] Existing ZSK files present but unreadable; refusing to regenerate",
			"domain", domain, "error", err,
			"hint", "check file permissions / ownership, or remove the zone and re-add to mint fresh keys")
		return nil, nil, fmt.Errorf("ZSK recovery failed for %s (refusing to regenerate): %w", domain, err)
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
	dnskey, priv, err := kg.loadKeyPairFromPath(baseName)
	if err != nil {
		return nil, nil, err
	}
	if err := validateLoadedKey(dnskey, domain, keyType); err != nil {
		return nil, nil, fmt.Errorf("%s key for %s: %w", keyType, domain, err)
	}
	return dnskey, priv, nil
}

// LoadPublicKey loads only the public half of a key. Callers that just need
// to display or compute DS/DNSKEY records (CLI output, web UI, registrar
// pushes, validation) should use this instead of LoadKeyPair so private key
// files aren't read — and don't need to be readable — on those paths.
func (kg *KeyGenerator) LoadPublicKey(domain, keyType string) (*dns.DNSKEY, error) {
	keysDir := kg.cfg.KeysDir()
	dnskey, err := kg.loadPublicKeyFromPath(filepath.Join(keysDir, fmt.Sprintf("%s.%s", domain, keyType)))
	if err != nil {
		return nil, err
	}
	if err := validateLoadedKey(dnskey, domain, keyType); err != nil {
		return nil, fmt.Errorf("%s key for %s: %w", keyType, domain, err)
	}
	return dnskey, nil
}

// LoadPublicKeyByID loads the public half of a backed-up key by its key tag
// (the rollover backup naming convention: <domain>.<type>.<tag>.key).
func (kg *KeyGenerator) LoadPublicKeyByID(domain, keyType string, keyID uint16) (*dns.DNSKEY, error) {
	keysDir := kg.cfg.KeysDir()
	dnskey, err := kg.loadPublicKeyFromPath(filepath.Join(keysDir, fmt.Sprintf("%s.%s.%d", domain, keyType, keyID)))
	if err != nil {
		return nil, err
	}
	if err := validateLoadedKey(dnskey, domain, keyType); err != nil {
		return nil, fmt.Errorf("%s key %d for %s: %w", keyType, keyID, domain, err)
	}
	return dnskey, nil
}

func (kg *KeyGenerator) loadPublicKeyFromPath(baseName string) (*dns.DNSKEY, error) {
	keyData, err := os.ReadFile(baseName + ".key")
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	dnskey, err := parseDNSKEYFromFile(string(keyData))
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	return dnskey, nil
}

// validateLoadedKey rejects a DNSKEY loaded from disk that does not match the
// domain and role it was loaded for: the owner name must be the zone apex, the
// flags must match the role (257 for a KSK, 256 for a ZSK), and the algorithm
// must be one this signer supports. Without this a wrong file — a mismatched
// owner, a ZSK in a KSK slot, or an unexpected algorithm — would be used
// silently (R-061). The signer's own generated keys always satisfy this.
func validateLoadedKey(dnskey *dns.DNSKEY, domain, keyType string) error {
	if !strings.EqualFold(dnskey.Hdr.Name, dns.Fqdn(domain)) {
		return fmt.Errorf("key owner %q does not match zone %q", dnskey.Hdr.Name, dns.Fqdn(domain))
	}
	var wantFlags uint16
	switch keyType {
	case "ksk":
		wantFlags = 257
	case "zsk":
		wantFlags = 256
	default:
		return fmt.Errorf("unknown key role %q", keyType)
	}
	if dnskey.Flags != wantFlags {
		return fmt.Errorf("key flags %d do not match role %q (want %d)", dnskey.Flags, keyType, wantFlags)
	}
	switch dnskey.Algorithm {
	case dns.ED25519, dns.ECDSAP256SHA256, dns.ECDSAP384SHA384:
	default:
		return fmt.Errorf("unsupported key algorithm %d in %s key for %s", dnskey.Algorithm, keyType, domain)
	}
	return nil
}

// fileExists reports whether path exists (as any file type).
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// loadKeyPairByID loads a backup key pair by its key ID
func (kg *KeyGenerator) loadKeyPairByID(domain, keyType string, keyID uint16) (*dns.DNSKEY, []byte, error) {
	keysDir := kg.cfg.KeysDir()
	baseName := filepath.Join(keysDir, fmt.Sprintf("%s.%s.%d", domain, keyType, keyID))
	dnskey, priv, err := kg.loadKeyPairFromPath(baseName)
	if err != nil {
		return nil, nil, err
	}
	if err := validateLoadedKey(dnskey, domain, keyType); err != nil {
		return nil, nil, fmt.Errorf("%s key %d for %s: %w", keyType, keyID, domain, err)
	}
	return dnskey, priv, nil
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

	// R-009: reject a mismatched pair (e.g. a new .key beside a stale .private left by a
	// crashed write) before it is used to sign. The ECDSA signing path derives the public
	// point from the private scalar, so a mismatch would otherwise "sign" and emit RRSIGs
	// that don't verify against the published DNSKEY — a silent SERVFAIL.
	if err := verifyKeyPairCorrespondence(dnskey, privateKey); err != nil {
		return nil, nil, fmt.Errorf("key pair at %s: %w", baseName, err)
	}

	return dnskey, privateKey, nil
}

// statExists reports whether path exists, distinguishing a genuine absence (false, nil)
// from a stat error such as permission denied (false, err).
func statExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
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

// verifyKeyPairCorrespondence checks that the private key material actually corresponds to
// the public key in the DNSKEY. Two failures this guards against: a crash or restore can
// pair a freshly written .key with a stale .private of a different key (R-009), and a
// standard BIND/ldns ED25519 key stores the private half as a 32-byte seed the raw signer
// would otherwise reject (R-010). It accepts every key form this signer generates or
// imports: 64-byte or 32-byte-seed ED25519, and 32/48-byte ECDSA P-256/P-384.
func verifyKeyPairCorrespondence(dnskey *dns.DNSKEY, privateKey []byte) error {
	pubBytes, err := base64.StdEncoding.DecodeString(dnskey.PublicKey)
	if err != nil {
		return fmt.Errorf("decoding DNSKEY public key: %w", err)
	}

	switch dnskey.Algorithm {
	case dns.ED25519:
		var derived ed25519.PublicKey
		switch len(privateKey) {
		case ed25519.SeedSize: // 32-byte seed (BIND/ldns/RFC 8080)
			derived = ed25519.NewKeyFromSeed(privateKey).Public().(ed25519.PublicKey)
		case ed25519.PrivateKeySize: // 64-byte expanded key
			derived = ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)
		default:
			return fmt.Errorf("invalid ED25519 private key length %d (want %d or %d)", len(privateKey), ed25519.SeedSize, ed25519.PrivateKeySize)
		}
		if len(pubBytes) != ed25519.PublicKeySize || !bytes.Equal(derived, pubBytes) {
			return fmt.Errorf("ED25519 private key does not correspond to the DNSKEY public key (key tag %d)", dnskey.KeyTag())
		}
		return nil
	case dns.ECDSAP256SHA256:
		return verifyECDSACorrespondence(elliptic.P256(), 32, privateKey, pubBytes, dnskey.KeyTag())
	case dns.ECDSAP384SHA384:
		return verifyECDSACorrespondence(elliptic.P384(), 48, privateKey, pubBytes, dnskey.KeyTag())
	default:
		return fmt.Errorf("unsupported algorithm %d for key-pair verification", dnskey.Algorithm)
	}
}

// verifyECDSACorrespondence derives the public point from an ECDSA private scalar and
// compares it to the DNSKEY's X||Y public key. size is the coordinate/scalar byte length
// (32 for P-256, 48 for P-384).
func verifyECDSACorrespondence(curve elliptic.Curve, size int, privateKey, pubBytes []byte, keyTag uint16) error {
	if len(privateKey) != size {
		return fmt.Errorf("invalid ECDSA private key length %d (want %d)", len(privateKey), size)
	}
	if len(pubBytes) != 2*size {
		return fmt.Errorf("invalid ECDSA public key length %d (want %d)", len(pubBytes), 2*size)
	}
	x, y := curve.ScalarBaseMult(privateKey)
	derived := make([]byte, 2*size)
	x.FillBytes(derived[:size])
	y.FillBytes(derived[size:])
	if !bytes.Equal(derived, pubBytes) {
		return fmt.Errorf("ECDSA private key does not correspond to the DNSKEY public key (key tag %d)", keyTag)
	}
	return nil
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

// AlgorithmFromName returns the algorithm number from name, restricted to the
// three algorithms this signer can actually generate and sign with (ED25519 and
// ECDSA P-256/P-384). RSA names are intentionally rejected: generateDNSSECKey /
// signRRSIG cannot produce or sign RSA keys, so advertising RSASHA256/RSASHA512
// here would be a false promise (R-062). Keep this set in lockstep with the
// key-generation and signing code.
// Returns an error if the algorithm name is not recognized.
func AlgorithmFromName(name string) (uint8, error) {
	names := map[string]uint8{
		"ED25519":         dns.ED25519,
		"ECDSAP256SHA256": dns.ECDSAP256SHA256,
		"ECDSAP384SHA384": dns.ECDSAP384SHA384,
	}
	alg, ok := names[name]
	if !ok {
		return 0, fmt.Errorf("unsupported algorithm: %q (supported: ED25519, ECDSAP256SHA256, ECDSAP384SHA384)", name)
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
