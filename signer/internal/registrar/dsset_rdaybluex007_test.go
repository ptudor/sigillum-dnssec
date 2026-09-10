package registrar

import (
	"path/filepath"
	"testing"

	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-007: the desired DS set is phase-aware. The old KSK's DS is part
// of it only while the rollover phase still requires it at the parent.

func TestRDAYBLUEX007_IncludesOldDSPhaseTable(t *testing.T) {
	cases := []struct {
		typ, state string
		want       bool
	}{
		{"ksk", statepkg.KSKRolloverStateDSAddWait, true},
		{"ksk", statepkg.KSKRolloverStateDSPropagation, false},
		{"ksk", statepkg.KSKRolloverStateRetiring, false},
		{"algorithm", statepkg.AlgoRolloverStateDSAddWait, true},
		{"algorithm", statepkg.AlgoRolloverStateDSPropagation, true},
		{"algorithm", statepkg.AlgoRolloverStateOldDSRemoval, false},
		{"algorithm", statepkg.AlgoRolloverStateRetiring, false},
		{"zsk", statepkg.ZSKRolloverStatePrePublish, false},
		{"zsk", statepkg.ZSKRolloverStateSigning, false},
	}
	if IncludesOldDS(nil) {
		t.Fatal("no rollover: active KSK only")
	}
	for _, c := range cases {
		if got := IncludesOldDS(&statepkg.RolloverState{Type: c.typ, State: c.state}); got != c.want {
			t.Errorf("%s/%s: IncludesOldDS = %v, want %v", c.typ, c.state, got, c.want)
		}
	}
}

// Through real key material: BuildDSSet yields exactly the DS identities the
// phase requires, for ordinary, KSK and algorithm rollover states.
func TestRDAYBLUEX007_BuildDSSetByPhase(t *testing.T) {
	dir := t.TempDir()
	cfg := dnssectest.Config(t, dir)
	cfg.Registrar.DigestTypeVal = 2
	if err := signerpkg.EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	domain := "phase.example"
	kg := signerpkg.NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	state := statepkg.NewState(filepath.Join(dir, "state.json"))
	state.SetZone(domain, &statepkg.ZoneState{Path: "/z", KSK: ksk, ZSK: zsk})
	oldTag := ksk.ID

	tags := func(t *testing.T) map[uint16]bool {
		t.Helper()
		set, err := BuildDSSet(cfg, state, domain)
		if err != nil {
			t.Fatal(err)
		}
		out := map[uint16]bool{}
		for _, ds := range set {
			out[ds.KeyTag] = true
		}
		return out
	}

	// Ordinary: active KSK only.
	if got := tags(t); len(got) != 1 || !got[oldTag] {
		t.Fatalf("no rollover: active KSK only, got %v", got)
	}

	// KSK rollover through its phases (real staged keys so the old KSK's
	// backup is loadable).
	rm := signerpkg.NewRolloverManager(cfg, state)
	if err := rm.StartKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	zs := state.GetZone(domain)
	newTag := zs.Rollover.NewKeyID
	if got := tags(t); len(got) != 2 || !got[oldTag] || !got[newTag] {
		t.Fatalf("ksk ds_add_wait: old+new, got %v", got)
	}
	for _, phase := range []string{statepkg.KSKRolloverStateDSPropagation, statepkg.KSKRolloverStateRetiring} {
		state.Mutate(func() { zs.Rollover.State = phase })
		if got := tags(t); len(got) != 1 || !got[newTag] {
			t.Fatalf("ksk %s: new only, got %v", phase, got)
		}
	}

	// Algorithm rollover phases: reuse the same two generations under an
	// algorithm-typed record.
	state.Mutate(func() {
		zs.Rollover.Type = "algorithm"
		zs.Rollover.OldAlgorithm, zs.Rollover.NewAlgorithm = "ED25519", "ECDSAP256SHA256"
		zs.Rollover.OldZSKID, zs.Rollover.NewZSKID = zsk.ID, zsk.ID+1
	})
	for _, phase := range []string{statepkg.AlgoRolloverStateDSAddWait, statepkg.AlgoRolloverStateDSPropagation} {
		state.Mutate(func() { zs.Rollover.State = phase })
		if got := tags(t); len(got) != 2 || !got[oldTag] || !got[newTag] {
			t.Fatalf("algorithm %s: old+new, got %v", phase, got)
		}
	}
	for _, phase := range []string{statepkg.AlgoRolloverStateOldDSRemoval, statepkg.AlgoRolloverStateRetiring} {
		state.Mutate(func() { zs.Rollover.State = phase })
		if got := tags(t); len(got) != 1 || !got[newTag] {
			t.Fatalf("algorithm %s: new only, got %v", phase, got)
		}
	}
}
