package signer

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/fsutil"
)

// Key-file transactions (RA6X-002 / RA6X-023).
//
// Layout in the keys directory, per zone and role (ksk|zsk):
//
//	<domain>.<role>.key / .private          the LIVE pair: what signing loads
//	<domain>.<role>.<tag>.key / .private    the tag-named copy of one generation
//
// Every generation this signer writes goes to its tag-named slot FIRST
// (staged), is verified by reloading it exactly as signing would, and is only
// then copied over the live slot (activated). The persisted zone state names
// the generation that must be live — KeyState.ID, or RolloverState.NewKeyID for
// a pre-published ZSK — and rollover start saves that record BEFORE activating
// anything. Signing compares the live pair's key tag against the persisted
// identity and re-activates the tag-named copy when they differ, so a crash at
// any point leaves either the complete old generation or the complete intended
// generation on disk, never a third interpretation. No key file is ever deleted:
// material that cannot be verified is set aside under a unique name.
//
// The tag-named copy of the CURRENT live pair doubles as the rollover backup
// that the rollover signing phases load by ID. ensureVerifiedBackup guarantees
// that copy is complete, parseable, matches the live key and corresponds
// cryptographically before any live overwrite (RA6X-023).
//
// State-file compatibility: no new state fields are needed. Older state files
// carry the same key identities; older key directories simply lack a tag-named
// copy of the live generation, which ensureVerifiedBackup creates on demand.

// errLiveUnverifiable marks a live pair that cannot be loaded and verified.
var errLiveUnverifiable = errors.New("live key pair does not verify")

// backupConflictError reports that the tag-named slot for a key already holds a
// different key (a key-tag collision). The existing backup is never overwritten.
type backupConflictError struct {
	Base string
	Tag  uint16
}

func (e *backupConflictError) Error() string {
	return fmt.Sprintf("backup %s.key already holds a different key (key-tag %d collision); refusing to overwrite it", e.Base, e.Tag)
}

// liveBase is the path prefix of a role's live pair.
func (kg *KeyGenerator) liveBase(domain, keyType string) string {
	return filepath.Join(kg.cfg.KeysDir(), fmt.Sprintf("%s.%s", domain, keyType))
}

// taggedBase is the path prefix of one generation's tag-named pair.
func (kg *KeyGenerator) taggedBase(domain, keyType string, tag uint16) string {
	return filepath.Join(kg.cfg.KeysDir(), fmt.Sprintf("%s.%s.%d", domain, keyType, tag))
}

// fail is the fault-injection seam used by the transaction tests: it returns
// the injected error for a step ("stage:ksk", "activate:zsk", ...) or nil.
func (kg *KeyGenerator) fail(step string) error {
	if kg.failpoint == nil {
		return nil
	}
	return kg.failpoint(step)
}

// samePublicKey reports whether two DNSKEYs carry the same key material for the
// same owner and role.
func samePublicKey(a, b *dns.DNSKEY) bool {
	return a != nil && b != nil &&
		a.PublicKey == b.PublicKey &&
		a.Algorithm == b.Algorithm &&
		a.Flags == b.Flags &&
		a.Protocol == b.Protocol &&
		strings.EqualFold(a.Hdr.Name, b.Hdr.Name)
}

// pairFiles reports which halves of a pair exist, failing closed on any stat
// error other than absence (an unreadable directory must not read as "absent").
func pairFiles(base string) (keyExists, privExists bool, err error) {
	if keyExists, err = statExists(base + ".key"); err != nil {
		return false, false, fmt.Errorf("stat %s.key: %w", base, err)
	}
	if privExists, err = statExists(base + ".private"); err != nil {
		return false, false, fmt.Errorf("stat %s.private: %w", base, err)
	}
	return keyExists, privExists, nil
}

// loadVerifiedPair loads a pair from base and applies every check signing
// relies on: both halves parse, the halves correspond cryptographically, and the
// public key carries the expected owner, role flags and a supported algorithm.
func (kg *KeyGenerator) loadVerifiedPair(base, domain, keyType string) (*dns.DNSKEY, []byte, error) {
	dnskey, priv, err := kg.loadKeyPairFromPath(base)
	if err != nil {
		return nil, nil, err
	}
	if err := validateLoadedKey(dnskey, domain, keyType); err != nil {
		return nil, nil, fmt.Errorf("%s key for %s at %s: %w", keyType, domain, base, err)
	}
	return dnskey, priv, nil
}

// setAside renames an unusable key file to a unique "<path>.<reason>.N" name so
// it stays available for diagnosis without occupying the slot.
func setAside(path, reason string) (string, error) {
	for i := 0; i < 10000; i++ {
		dst := fmt.Sprintf("%s.%s.%d", path, reason, i)
		if FileExists(dst) {
			continue
		}
		if err := os.Rename(path, dst); err != nil {
			return "", fmt.Errorf("setting aside %s: %w", path, err)
		}
		slog.Warn("[KEY] Set aside an unusable key file for diagnosis", "path", path, "moved_to", dst)
		return dst, nil
	}
	return "", fmt.Errorf("could not allocate a name to set aside %s", path)
}

// copyDurable copies one key file atomically and requires the copy to be
// durable: a backup or staged half that might vanish on power loss is not a
// backup.
func copyDurable(src, dst string) error {
	if err := fsutil.CopyFile(src, dst); err != nil {
		return fmt.Errorf("copying %s to %s: %w", src, dst, err)
	}
	return nil
}

// copyPairUnique preserves whichever halves exist at srcBase under a fresh
// "<prefix>.N" base. Used when the live slot holds material that has no
// verified tag-named home: a pair that does not verify, a lone half, or a key
// whose tag slot is occupied by a different key.
func copyPairUnique(srcBase, prefix string) (string, error) {
	dst, err := uniqueBackupBase(prefix)
	if err != nil {
		return "", err
	}
	for _, ext := range []string{".key", ".private"} {
		exists, err := statExists(srcBase + ext)
		if err != nil {
			return "", fmt.Errorf("stat %s%s: %w", srcBase, ext, err)
		}
		if !exists {
			continue
		}
		if err := copyDurable(srcBase+ext, dst+ext); err != nil {
			return "", err
		}
	}
	slog.Warn("[KEY] Preserved live key material under a unique name before overwrite",
		"live", srcBase, "preserved_as", dst)
	return dst, nil
}

// StageKeyPair writes a generation to its tag-named slot and verifies it. The
// live pair is not touched. A slot already holding the SAME key is reused (a
// retried transaction), with a broken private half set aside and rewritten; a
// slot holding a different key is a key-tag collision and is never overwritten.
// Both halves are written atomically and durably before the pair is reloaded
// exactly as signing would load it.
func (kg *KeyGenerator) StageKeyPair(domain, keyType string, dnskey *dns.DNSKEY, privateKey []byte) (string, error) {
	if err := validateLoadedKey(dnskey, domain, keyType); err != nil {
		return "", fmt.Errorf("refusing to stage %s key for %s: %w", keyType, domain, err)
	}
	if err := VerifyKeyPairCorrespondence(dnskey, privateKey); err != nil {
		return "", fmt.Errorf("refusing to stage %s key for %s: %w", keyType, domain, err)
	}
	if err := EnsureDirSecure(kg.cfg.KeysDir()); err != nil {
		return "", err
	}
	if err := kg.fail("stage:" + keyType); err != nil {
		return "", err
	}

	tag := dnskey.KeyTag()
	base := kg.taggedBase(domain, keyType, tag)
	keyExists, privExists, err := pairFiles(base)
	if err != nil {
		return "", err
	}
	if keyExists {
		existing, err := kg.loadPublicKeyFromPath(base)
		if err != nil || !samePublicKey(existing, dnskey) {
			return "", fmt.Errorf("refusing to stage %s key %d for %s: %s.key already holds a different key (key-tag collision); leaving it untouched", keyType, tag, domain, base)
		}
		if privExists {
			if _, _, verr := kg.loadVerifiedPair(base, domain, keyType); verr == nil {
				slog.Debug("[KEY] Generation already staged and verified", "domain", domain, "type", keyType, "key_tag", tag)
				return base, nil
			}
			if _, err := setAside(base+".private", "invalid"); err != nil {
				return "", err
			}
		}
	} else if privExists {
		if _, err := setAside(base+".private", "orphan"); err != nil {
			return "", err
		}
	}

	keyContent := fmt.Sprintf("; Key tag: %d\n; Algorithm: %s\n; Created: %s\n%s\n",
		tag, AlgorithmName(dnskey.Algorithm), time.Now().UTC().Format(time.RFC3339), dnskey.String())
	privContent := formatPrivateKey(dnskey, privateKey)
	if err := fsutil.WriteFileAtomicOwned(base+".private", []byte(privContent), 0600); err != nil {
		return "", fmt.Errorf("staging private key %s.private: %w", base, err)
	}
	if err := fsutil.WriteFileAtomicOwned(base+".key", []byte(keyContent), 0644); err != nil {
		return "", fmt.Errorf("staging public key %s.key: %w", base, err)
	}

	staged, _, err := kg.loadVerifiedPair(base, domain, keyType)
	if err != nil {
		return "", fmt.Errorf("staged %s key %d for %s does not reload: %w", keyType, tag, domain, err)
	}
	if !samePublicKey(staged, dnskey) || staged.KeyTag() != tag {
		return "", fmt.Errorf("staged %s key for %s at %s does not match the generated key", keyType, domain, base)
	}
	slog.Debug("[KEY] Staged key pair", "domain", domain, "type", keyType, "key_tag", tag)
	return base, nil
}

// ActivateKeyPair makes a verified tag-named generation the live pair. Whatever
// currently occupies the live slot is preserved first (see preserveLivePair),
// then the staged halves are copied over the live files atomically — .private
// before .key, so a crash between the two leaves a pair that fails the
// correspondence check and is repaired by the next signing run rather than a
// pair that silently signs with the wrong key. Idempotent: a live slot that
// already holds the generation is left alone.
func (kg *KeyGenerator) ActivateKeyPair(domain, keyType string, tag uint16) error {
	staged := kg.taggedBase(domain, keyType, tag)
	stagedKey, _, err := kg.loadVerifiedPair(staged, domain, keyType)
	if err != nil {
		return fmt.Errorf("cannot activate %s key %d for %s: staged pair at %s does not verify: %w", keyType, tag, domain, staged, err)
	}
	if stagedKey.KeyTag() != tag {
		return fmt.Errorf("cannot activate %s key %d for %s: %s holds key tag %d", keyType, tag, domain, staged, stagedKey.KeyTag())
	}

	live := kg.liveBase(domain, keyType)
	if cur, _, err := kg.loadVerifiedPair(live, domain, keyType); err == nil && samePublicKey(cur, stagedKey) {
		return nil
	}
	if err := kg.preserveLivePair(domain, keyType); err != nil {
		return fmt.Errorf("preserving the current live %s key for %s before activation: %w", keyType, domain, err)
	}
	if err := kg.fail("activate:" + keyType); err != nil {
		return err
	}
	if err := fsutil.CopyFile(staged+".private", live+".private"); err != nil && !durabilityWarning(err, live+".private") {
		return fmt.Errorf("activating %s private key for %s: %w", keyType, domain, err)
	}
	if err := kg.fail("activate-mid:" + keyType); err != nil {
		return err
	}
	if err := fsutil.CopyFile(staged+".key", live+".key"); err != nil && !durabilityWarning(err, live+".key") {
		return fmt.Errorf("activating %s public key for %s: %w", keyType, domain, err)
	}

	now, _, err := kg.loadVerifiedPair(live, domain, keyType)
	if err != nil {
		return fmt.Errorf("live %s key for %s does not verify after activation: %w", keyType, domain, err)
	}
	if !samePublicKey(now, stagedKey) {
		return fmt.Errorf("live %s key for %s does not match the activated generation %d", keyType, domain, tag)
	}
	slog.Info("[KEY] Activated key pair", "domain", domain, "type", keyType, "key_tag", tag)
	return nil
}

// preserveLivePair guarantees that whatever occupies the live slot survives an
// overwrite. A verifiable pair gets (or already has) a verified tag-named copy;
// a pair whose tag slot is taken by a different key, a pair that does not
// verify, or a lone half is copied under a unique name. Nothing is deleted.
func (kg *KeyGenerator) preserveLivePair(domain, keyType string) error {
	live := kg.liveBase(domain, keyType)
	keyExists, privExists, err := pairFiles(live)
	if err != nil {
		return err
	}
	switch {
	case !keyExists && !privExists:
		return nil
	case keyExists && privExists:
		_, err := kg.ensureVerifiedBackup(domain, keyType)
		var conflict *backupConflictError
		switch {
		case err == nil:
			return nil
		case errors.As(err, &conflict):
			_, err := copyPairUnique(live, conflict.Base)
			return err
		case errors.Is(err, errLiveUnverifiable):
			slog.Warn("[KEY] Live key pair does not verify; preserving it under a unique .bak name",
				"domain", domain, "type", keyType, "error", err)
			_, err := copyPairUnique(live, live+".bak")
			return err
		default:
			return err
		}
	default:
		slog.Warn("[KEY] Live key slot holds only one half of a pair; preserving it under a unique .bak name",
			"domain", domain, "type", keyType)
		_, err := copyPairUnique(live, live+".bak")
		return err
	}
}

// ensureVerifiedBackup guarantees that the live pair has a complete, verified
// tag-named copy and returns the live public key (RA6X-023). The live pair
// itself must load and verify (else errLiveUnverifiable). A tag slot holding a
// different key yields *backupConflictError and is never overwritten. A
// missing, empty, truncated or mismatched private half is set aside for
// diagnosis and rewritten atomically from the verified live pair; an unreadable
// half is an error, since a backup that cannot be read cannot be trusted.
func (kg *KeyGenerator) ensureVerifiedBackup(domain, keyType string) (*dns.DNSKEY, error) {
	live := kg.liveBase(domain, keyType)
	dnskey, _, err := kg.loadVerifiedPair(live, domain, keyType)
	if err != nil {
		return nil, fmt.Errorf("%w: %s pair for %s: %w", errLiveUnverifiable, keyType, domain, err)
	}
	if err := kg.fail("backup:" + keyType); err != nil {
		return nil, err
	}
	backup := kg.taggedBase(domain, keyType, dnskey.KeyTag())
	if err := kg.ensureBackupAt(domain, keyType, live, backup, dnskey); err != nil {
		return nil, err
	}
	return dnskey, nil
}

func (kg *KeyGenerator) ensureBackupAt(domain, keyType, live, backup string, want *dns.DNSKEY) error {
	keyExists, privExists, err := pairFiles(backup)
	if err != nil {
		return err
	}
	if keyExists {
		data, err := os.ReadFile(backup + ".key")
		if err != nil {
			return fmt.Errorf("reading backup %s.key: %w", backup, err)
		}
		parsed, perr := ParseDNSKEYFromFile(string(data))
		if perr != nil || !samePublicKey(parsed, want) {
			return &backupConflictError{Base: backup, Tag: want.KeyTag()}
		}
	} else {
		if privExists {
			if _, err := setAside(backup+".private", "orphan"); err != nil {
				return err
			}
			privExists = false
		}
		if err := copyDurable(live+".key", backup+".key"); err != nil {
			return fmt.Errorf("backing up %s public key for %s: %w", keyType, domain, err)
		}
	}

	if privExists {
		data, err := os.ReadFile(backup + ".private")
		if err != nil {
			return fmt.Errorf("reading backup %s.private: %w", backup, err)
		}
		valid := false
		if priv, perr := ParsePrivateKeyFromFile(string(data)); perr == nil {
			valid = VerifyKeyPairCorrespondence(want, priv) == nil
		}
		if !valid {
			slog.Warn("[KEY] Backup private key is incomplete or does not match its public half; repairing from the verified live pair",
				"domain", domain, "type", keyType, "key_tag", want.KeyTag(), "backup", backup)
			if _, err := setAside(backup+".private", "invalid"); err != nil {
				return err
			}
			privExists = false
		}
	}
	if !privExists {
		if err := copyDurable(live+".private", backup+".private"); err != nil {
			return fmt.Errorf("backing up %s private key for %s: %w", keyType, domain, err)
		}
	}

	got, _, err := kg.loadVerifiedPair(backup, domain, keyType)
	if err != nil {
		return fmt.Errorf("backup of %s key %d for %s at %s does not verify: %w", keyType, want.KeyTag(), domain, backup, err)
	}
	if !samePublicKey(got, want) {
		return fmt.Errorf("backup of %s key for %s at %s does not hold the live key", keyType, domain, backup)
	}
	return nil
}

// EnsureLiveKey loads the live pair for a role and checks it against the key
// identity the persisted state expects. When the live slot holds a different
// generation or does not verify, the tag-named copy of the expected generation
// is re-activated — the deterministic restart recovery for a rollover
// interrupted between its state save and its activation (RA6X-002). Without a
// verified copy of the expected generation it fails closed so the previous
// signed zone keeps serving.
func (kg *KeyGenerator) EnsureLiveKey(domain, keyType string, expected uint16) (*dns.DNSKEY, []byte, error) {
	live := kg.liveBase(domain, keyType)
	dnskey, priv, liveErr := kg.loadVerifiedPair(live, domain, keyType)
	if liveErr == nil && dnskey.KeyTag() == expected {
		return dnskey, priv, nil
	}

	var liveDetail string
	if liveErr != nil {
		liveDetail = fmt.Sprintf("the live pair does not verify (%v)", liveErr)
	} else {
		liveDetail = fmt.Sprintf("the live pair holds key tag %d", dnskey.KeyTag())
	}
	tagged := kg.taggedBase(domain, keyType, expected)
	tk, _, terr := kg.loadVerifiedPair(tagged, domain, keyType)
	if terr != nil || tk.KeyTag() != expected {
		if terr == nil {
			terr = fmt.Errorf("%s holds key tag %d", tagged, tk.KeyTag())
		}
		return nil, nil, fmt.Errorf("%s key for %s: state expects key tag %d but %s, and no verified copy of key %d exists (%v); refusing to sign with a key the recorded state does not name",
			keyType, domain, expected, liveDetail, expected, terr)
	}
	slog.Warn("[KEY] Live key does not match the persisted key identity; re-activating the recorded generation",
		"domain", domain, "type", keyType, "expected_key_tag", expected, "live", liveDetail)
	if err := kg.ActivateKeyPair(domain, keyType, expected); err != nil {
		return nil, nil, fmt.Errorf("re-activating %s key %d for %s: %w", keyType, expected, domain, err)
	}
	dnskey, priv, err := kg.loadVerifiedPair(live, domain, keyType)
	if err != nil {
		return nil, nil, fmt.Errorf("%s key for %s after re-activation: %w", keyType, domain, err)
	}
	if dnskey.KeyTag() != expected {
		return nil, nil, fmt.Errorf("%s key for %s after re-activation holds key tag %d, expected %d", keyType, domain, dnskey.KeyTag(), expected)
	}
	return dnskey, priv, nil
}

// ValidateKeyForImport applies every check an imported key must pass before
// any live artifact changes (RA6X-024): canonical owner, protocol 3, a
// supported algorithm, the flags of the requested role, private/public
// correspondence, and actual signing capability — a signature made with the
// private key must verify under the public key.
func ValidateKeyForImport(domain, keyType string, dnskey *dns.DNSKEY, privateKey []byte) error {
	if dnskey == nil {
		return fmt.Errorf("%s for %s: no DNSKEY", keyType, domain)
	}
	if err := validateLoadedKey(dnskey, domain, keyType); err != nil {
		return fmt.Errorf("%s for %s: %w", keyType, domain, err)
	}
	if dnskey.Protocol != 3 {
		return fmt.Errorf("%s for %s: DNSKEY protocol %d is not 3 (RFC 4034 §2.1.2)", keyType, domain, dnskey.Protocol)
	}
	if err := VerifyKeyPairCorrespondence(dnskey, privateKey); err != nil {
		return fmt.Errorf("%s for %s: %w", keyType, domain, err)
	}
	probe := []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: dns.Fqdn(domain), Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
		Txt: []string{"dnssec-tudor import signing probe"},
	}}
	s := &Signer{}
	now := time.Now().UTC()
	rrsig := s.createRRSIG(probe, dnskey, dns.Fqdn(domain), now.Add(-time.Hour), now.Add(time.Hour))
	if err := s.signRRSIG(rrsig, probe, dnskey, privateKey); err != nil {
		return fmt.Errorf("%s for %s cannot sign: %w", keyType, domain, err)
	}
	if err := rrsig.Verify(dnskey, probe); err != nil {
		return fmt.Errorf("%s for %s: a signature made with the private key does not verify under the public key: %w", keyType, domain, err)
	}
	return nil
}
