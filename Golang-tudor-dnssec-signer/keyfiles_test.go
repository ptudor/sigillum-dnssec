package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// R-028: exactly one half of a key pair present must refuse recovery (not silently
// regenerate a new KSK, which would break the DS chain), and the surviving half stays.
func TestRecoverKeyState_OrphanHalf(t *testing.T) {
	for _, deleted := range []string{".private", ".key"} {
		t.Run("missing"+deleted, func(t *testing.T) {
			dataDir := t.TempDir()
			cfg := testConfig(t, dataDir)
			keyGen := NewKeyGenerator(cfg)
			if _, err := keyGen.GenerateKSK("example.com"); err != nil {
				t.Fatal(err)
			}
			base := filepath.Join(cfg.KeysDir(), "example.com.ksk")

			if err := os.Remove(base + deleted); err != nil {
				t.Fatal(err)
			}
			surviving := base + ".key"
			if deleted == ".key" {
				surviving = base + ".private"
			}

			state, err := keyGen.RecoverKeyState("example.com", true)
			if err == nil {
				t.Fatal("RecoverKeyState must error on an orphan half, not return (nil,nil)")
			}
			if state != nil {
				t.Fatal("RecoverKeyState must not return a state for an orphan half")
			}
			if !fileExists(surviving) {
				t.Fatalf("the surviving half %s must not be touched", surviving)
			}
			if _, _, err := recoverOrGenerateKeys(keyGen, "example.com"); err == nil {
				t.Fatal("recoverOrGenerateKeys must refuse to regenerate over an orphan half")
			}
		})
	}
}

// R-009: a .key that does not correspond to its .private (e.g. a crashed write pairing a
// new public key with a stale private key) must be rejected at load, not signed with.
func TestLoadKeyPair_MismatchedPairRejected(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	keyGen := NewKeyGenerator(cfg)
	if _, err := keyGen.GenerateKSK("a.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := keyGen.GenerateKSK("b.example.com"); err != nil {
		t.Fatal(err)
	}

	aKey := filepath.Join(cfg.KeysDir(), "a.example.com.ksk.key")
	bKey := filepath.Join(cfg.KeysDir(), "b.example.com.ksk.key")

	bKeyData, err := os.ReadFile(bKey)
	if err != nil {
		t.Fatal(err)
	}
	// Pair a's .private with b's public .key: they no longer correspond.
	if err := os.WriteFile(aKey, bKeyData, 0644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := keyGen.LoadKeyPair("a.example.com", "ksk"); err == nil {
		t.Fatal("LoadKeyPair must reject a .key/.private pair that does not correspond")
	}
}

// R-027: if the pre-overwrite backup cannot be written, key generation must abort and
// leave the existing (live) key files byte-for-byte intact.
func TestSaveKeyFiles_BackupFailureAborts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("relies on filesystem permissions; not meaningful as root")
	}
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	keyGen := NewKeyGenerator(cfg)
	if _, err := keyGen.GenerateKSK("example.com"); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(cfg.KeysDir(), "example.com.ksk")
	origKey, _ := os.ReadFile(base + ".key")
	origPriv, _ := os.ReadFile(base + ".private")

	// Read-only keys dir → the backup rename fails.
	if err := os.Chmod(cfg.KeysDir(), 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(cfg.KeysDir(), 0700)

	if _, err := keyGen.GenerateKSK("example.com"); err == nil {
		t.Fatal("GenerateKSK must fail when the pre-overwrite backup cannot be written")
	}

	os.Chmod(cfg.KeysDir(), 0700)
	nowKey, _ := os.ReadFile(base + ".key")
	nowPriv, _ := os.ReadFile(base + ".private")
	if !bytes.Equal(origKey, nowKey) || !bytes.Equal(origPriv, nowPriv) {
		t.Fatal("original key files must be untouched after a failed backup")
	}
}

// R-027: a backup failure at rollover start is fatal and leaves no rollover state.
func TestStartKSKRollover_BackupFailureFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("relies on filesystem permissions; not meaningful as root")
	}
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	keyGen := NewKeyGenerator(cfg)
	ksk, err := keyGen.GenerateKSK("example.com")
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := keyGen.GenerateZSK("example.com")
	if err != nil {
		t.Fatal(err)
	}

	state := statepkg.NewState(filepath.Join(dataDir, "state.json"))
	state.SetZone("example.com", &statepkg.ZoneState{Path: filepath.Join(dataDir, "zone.db"), KSK: ksk, ZSK: zsk})
	rm := NewRolloverManager(cfg, state)

	if err := os.Chmod(cfg.KeysDir(), 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(cfg.KeysDir(), 0700)

	if err := rm.StartKSKRollover("example.com"); err == nil {
		t.Fatal("StartKSKRollover must fail when the old-KSK backup cannot be written")
	}
	os.Chmod(cfg.KeysDir(), 0700)
	if r := state.GetZone("example.com").Rollover; r != nil {
		t.Fatalf("no rollover state must be set after a failed start, got %+v", r)
	}
}
