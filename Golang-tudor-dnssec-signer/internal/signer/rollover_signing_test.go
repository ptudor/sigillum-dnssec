package signer

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// R-003: every rollover signing branch must be FATAL when the old key it depends on can't
// be loaded — publishing a DNSKEY RRset missing a key the parent DS/resolvers still
// reference is a silent bogus zone. Previously three of the four branches warned and
// signed anyway.
func TestLoadKeysForSigning_MissingOldKeyIsFatal(t *testing.T) {
	cases := []struct {
		name     string
		rollover *statepkg.RolloverState
	}{
		{
			name: "ksk ds_add_wait",
			rollover: &statepkg.RolloverState{
				Type: "ksk", State: statepkg.KSKRolloverStateDSAddWait,
				OldKeyID: 9999, NewKeyID: 1, Started: time.Now().UTC(),
			},
		},
		{
			name: "zsk signing phase",
			rollover: &statepkg.RolloverState{
				Type: "zsk", State: statepkg.ZSKRolloverStateSigning,
				OldKeyID: 9999, NewKeyID: 1, Started: time.Now().UTC(),
			},
		},
		{
			name: "algorithm ds_add_wait",
			rollover: &statepkg.RolloverState{
				Type: "algorithm", State: statepkg.AlgoRolloverStateDSAddWait,
				OldKeyID: 9999, NewKeyID: 1, OldZSKID: 8888, NewZSKID: 2,
				OldAlgorithm: "ECDSAP256SHA256", NewAlgorithm: "ED25519", Started: time.Now().UTC(),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			cfg := dnssectest.Config(t, dataDir)
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
			zoneState := &statepkg.ZoneState{
				Path:     filepath.Join(dataDir, "zone.db"),
				KSK:      ksk,
				ZSK:      zsk,
				Rollover: tc.rollover, // OldKeyID/OldZSKID reference backups that don't exist
			}
			state.SetZone("example.com", zoneState)
			s := NewSigner(cfg, state)

			if _, err := s.loadKeysForSigning("example.com", keyGen, zoneState); err == nil {
				t.Fatal("loadKeysForSigning must return an error when the old rollover key is missing")
			}
		})
	}
}
