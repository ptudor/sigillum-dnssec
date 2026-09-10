//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-033: a failed `add` removes only the key generations the
// transaction itself minted, and only while the live slot still holds
// exactly that generation; a preflight existence check that cannot be
// answered aborts the command instead of reading as "absent".

func TestRDAYBLUEX033_UnwindRemovesOnlyTransactionGenerations(t *testing.T) {
	dir := t.TempDir()
	cfg := dnssectest.Config(t, dir)
	for _, d := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := signerpkg.EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	keyGen := signerpkg.NewKeyGenerator(cfg)
	const domain = "roll.example."
	live := func(role, ext string) string { return filepath.Join(cfg.KeysDir(), domain+"."+role+ext) }

	// A pair "recovered from a previous management period" (generated here,
	// but not part of the transaction) must survive every rollback.
	recoveredKSK, err := keyGen.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	state := statepkg.NewState(cfg.StatePath())
	state.SetZone(domain, &statepkg.ZoneState{Path: "/zones/roll.db"})
	unwindAdd(cfg, state, domain, signerpkg.KeyGeneration{}, nil, false)
	if _, err := os.Stat(live("ksk", ".key")); err != nil {
		t.Fatal("a pair the transaction did not create must survive")
	}

	// A generation the transaction minted is removed — while the live slot
	// holds exactly it.
	minted, err := keyGen.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	if !keyGen.LivePairHoldsKeyTag(domain, "zsk", minted.ID) {
		t.Fatal("fixture: the live ZSK is the minted generation")
	}
	state.SetZone(domain, &statepkg.ZoneState{Path: "/zones/roll.db"})
	unwindAdd(cfg, state, domain, signerpkg.KeyGeneration{ZSK: minted}, nil, false)
	for _, ext := range []string{".key", ".private"} {
		if _, err := os.Stat(live("zsk", ext)); !os.IsNotExist(err) {
			t.Fatalf("the minted ZSK %s must be removed", ext)
		}
	}
	if _, err := os.Stat(live("ksk", ".key")); err != nil {
		t.Fatal("the recovered KSK must survive alongside")
	}

	// The transaction record names a generation the live slot no longer
	// holds (another key was activated since): nothing is removed.
	replaced, err := keyGen.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	stale := &statepkg.KeyState{ID: replaced.ID + 1}
	state.SetZone(domain, &statepkg.ZoneState{Path: "/zones/roll.db"})
	unwindAdd(cfg, state, domain, signerpkg.KeyGeneration{ZSK: stale, KSK: &statepkg.KeyState{ID: recoveredKSK.ID + 1}}, nil, false)
	for _, role := range []string{"ksk", "zsk"} {
		if _, err := os.Stat(live(role, ".key")); err != nil {
			t.Fatalf("a slot holding a different generation must be left alone (%s)", role)
		}
	}
	if !keyGen.LivePairHoldsKeyTag(domain, "zsk", replaced.ID) {
		t.Fatal("the live ZSK must still be the replacement generation")
	}
}

func TestRDAYBLUEX033_PreflightExistenceFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.Mkdir(keysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	absent, err := keyPairAbsent(keysDir, "x.example.", "ksk")
	if err != nil || !absent {
		t.Fatalf("an empty directory is a confirmed absence: %v %v", absent, err)
	}
	if err := os.WriteFile(filepath.Join(keysDir, "x.example..ksk.key"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	absent, err = keyPairAbsent(keysDir, "x.example.", "ksk")
	if err != nil || absent {
		t.Fatalf("a present half is not absent: %v %v", absent, err)
	}
	// Without search permission stat cannot answer: that is an error, never
	// "absent".
	if err := os.Chmod(keysDir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(keysDir, 0o700) })
	if _, err := keyPairAbsent(keysDir, "x.example.", "ksk"); err == nil || !errors.Is(err, syscall.EACCES) {
		t.Fatalf("EACCES must be returned: %v", err)
	}
}
