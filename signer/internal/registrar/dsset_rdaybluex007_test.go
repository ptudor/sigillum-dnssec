package registrar

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-007: the desired DS set is phase-aware. The old KSK's DS is part
// of it while the rollover phase still requires it at the parent — and, in
// every later phase, until the generation carrying the new key(s) has
// propagated (a stamped, elapsed horizon; RM51X-001).

func TestRDAYBLUEX007_IncludesOldDSPhaseTable(t *testing.T) {
	past := time.Now().Add(-time.Second)
	future := time.Now().Add(time.Hour)
	var unstamped time.Time
	cases := []struct {
		typ, state string
		horizon    time.Time
		want       bool
	}{
		{"ksk", statepkg.KSKRolloverStateDSAddWait, unstamped, true},
		{"ksk", statepkg.KSKRolloverStateDSAddWait, past, true},
		{"ksk", statepkg.KSKRolloverStateDSPropagation, unstamped, true},
		{"ksk", statepkg.KSKRolloverStateDSPropagation, future, true},
		{"ksk", statepkg.KSKRolloverStateDSPropagation, past, false},
		{"ksk", statepkg.KSKRolloverStateRetiring, unstamped, true},
		{"ksk", statepkg.KSKRolloverStateRetiring, past, false},
		{"algorithm", statepkg.AlgoRolloverStateDSAddWait, past, true},
		{"algorithm", statepkg.AlgoRolloverStateDSPropagation, past, true},
		{"algorithm", statepkg.AlgoRolloverStateOldDSRemoval, unstamped, true},
		{"algorithm", statepkg.AlgoRolloverStateOldDSRemoval, future, true},
		{"algorithm", statepkg.AlgoRolloverStateOldDSRemoval, past, false},
		{"algorithm", statepkg.AlgoRolloverStateRetiring, unstamped, true},
		{"algorithm", statepkg.AlgoRolloverStateRetiring, past, false},
		{"zsk", statepkg.ZSKRolloverStatePrePublish, past, false},
		{"zsk", statepkg.ZSKRolloverStateSigning, past, false},
	}
	if IncludesOldDS(nil) {
		t.Fatal("no rollover: active KSK only")
	}
	for _, c := range cases {
		r := &statepkg.RolloverState{Type: c.typ, State: c.state, PhaseHorizon: c.horizon}
		if got := IncludesOldDS(r); got != c.want {
			t.Errorf("%s/%s horizon=%v: IncludesOldDS = %v, want %v", c.typ, c.state, c.horizon, got, c.want)
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
		state.Mutate(func() { zs.Rollover.State = phase; zs.Rollover.PhaseHorizon = time.Time{} })
		if got := tags(t); len(got) != 2 || !got[oldTag] || !got[newTag] {
			t.Fatalf("ksk %s before the new DNSKEY RRset propagated: old+new, got %v", phase, got)
		}
		state.Mutate(func() { zs.Rollover.PhaseHorizon = time.Now().Add(-time.Second) })
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
		state.Mutate(func() { zs.Rollover.State = phase; zs.Rollover.PhaseHorizon = time.Time{} })
		if got := tags(t); len(got) != 2 || !got[oldTag] || !got[newTag] {
			t.Fatalf("algorithm %s before the new keys propagated: old+new, got %v", phase, got)
		}
		state.Mutate(func() { zs.Rollover.PhaseHorizon = time.Now().Add(-time.Second) })
		if got := tags(t); len(got) != 1 || !got[newTag] {
			t.Fatalf("algorithm %s: new only, got %v", phase, got)
		}
	}
}
