package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// RDAYBLUEX-019: ReloadFromDisk is a three-way merge against the last
// synchronized disk image, driven by an explicit per-zone revision, so an
// independent CLI mutation (a warning, an operation error, a publication
// confirmation, a rollover timestamp) and unsaved daemon work both survive.

func baseZone(now time.Time) *ZoneState {
	return &ZoneState{
		Revision: 3, Path: "/z/a.zone", Serial: 10, PublishedSerial: 10,
		LastSigned: now, SourceModTime: now.Add(-time.Minute), SourceSize: 100,
		SignaturesExp: now.Add(24 * time.Hour), PublishedDNSKEYTTL: 3600, PublishedMaxRRSIGTTL: 3600,
		PublishedAt: now, PublishedGenerationSignedAt: now, ServedDNSKEYTTL: 3600, ServedMaxRRSIGTTL: 3600,
		DNSKEYCacheHorizon: now.Add(time.Hour), RRSIGCacheHorizon: now.Add(time.Hour),
		KSK:      &KeyState{ID: 1, Algorithm: "ED25519", Created: now, Expires: now.Add(time.Hour)},
		ZSK:      &KeyState{ID: 2, Algorithm: "ED25519", Created: now, Expires: now.Add(time.Hour)},
		Warnings: []string{"w-kept", "w-mem-removes", "w-disk-removes"},
		Errors:   []string{"signing: old", "registrar: r1"},
	}
}

func TestMergeZone_DiskUnchangedKeepsMemory(t *testing.T) {
	now := time.Now().UTC()
	base := baseZone(now)
	disk := base.Clone()
	mem := base.Clone()
	mem.LastSigned = now.Add(time.Minute)
	mem.Warnings = nil
	if got := mergeZone(base, disk, mem); got != mem {
		t.Fatal("an unchanged disk must leave memory (with unsaved work) untouched")
	}
}

func TestMergeZone_MemoryCleanAdoptsDisk(t *testing.T) {
	now := time.Now().UTC()
	base := baseZone(now)
	disk := base.Clone()
	disk.Revision = 4
	disk.Warnings = append(disk.Warnings, "URGENT: zero DS")
	mem := base.Clone()
	if got := mergeZone(base, disk, mem); got != disk {
		t.Fatal("clean memory must adopt the newer disk")
	}
}

// The finding's scenario: memory signed (unsaved), the CLI persisted a warning
// at the same LastSigned. Both must survive.
func TestMergeZone_BothChanged_SigningAndDiagnostics(t *testing.T) {
	now := time.Now().UTC()
	base := baseZone(now)

	disk := base.Clone()
	disk.Revision = 4
	disk.Warnings = []string{"w-kept", "w-mem-removes", "URGENT: registrar left zero DS"} // disk removed w-disk-removes, added URGENT
	disk.Errors = []string{"signing: old", "registrar: r2"}                               // disk replaced the registrar error

	mem := base.Clone()
	mem.LastSigned = now.Add(time.Minute)
	mem.Serial, mem.PublishedSerial = 11, 11
	mem.SignaturesExp = now.Add(48 * time.Hour)
	mem.Warnings = []string{"w-kept", "w-disk-removes"} // memory removed w-mem-removes
	mem.Errors = []string{"registrar: r1"}              // memory cleared the signing error (successful sign)

	got := mergeZone(base, disk, mem)
	if !got.LastSigned.Equal(mem.LastSigned) || got.Serial != 11 || !got.SignaturesExp.Equal(mem.SignaturesExp) {
		t.Fatalf("memory's unsaved signing must survive: %+v", got)
	}
	wantW := []string{"w-kept", "URGENT: registrar left zero DS"}
	if !reflect.DeepEqual(got.Warnings, wantW) {
		t.Fatalf("warnings: got %v want %v", got.Warnings, wantW)
	}
	wantE := []string{"registrar: r2"}
	if !reflect.DeepEqual(got.Errors, wantE) {
		t.Fatalf("errors: got %v want %v (memory cleared signing, disk replaced registrar)", got.Errors, wantE)
	}
	if got.Revision != 4 {
		t.Fatalf("merged revision must carry the disk's, got %d", got.Revision)
	}
}

func TestMergeZone_BothSigned_LaterGenerationWins(t *testing.T) {
	now := time.Now().UTC()
	base := baseZone(now)
	disk := base.Clone()
	disk.Revision = 4
	disk.LastSigned = now.Add(2 * time.Minute)
	disk.Serial = 12
	disk.PublishedGenerationSignedAt, disk.PublishedAt = disk.LastSigned, disk.LastSigned
	mem := base.Clone()
	mem.LastSigned = now.Add(time.Minute)
	mem.Serial = 11
	mem.PendingPublication = true
	got := mergeZone(base, disk, mem)
	if got.Serial != 12 || !got.LastSigned.Equal(disk.LastSigned) {
		t.Fatalf("the later signing must win: %+v", got)
	}
	if got.PendingPublication {
		t.Fatal("the later generation was confirmed on disk; pending must be recomputed false")
	}

	// Reverse: memory is later.
	disk2 := base.Clone()
	disk2.Revision = 4
	disk2.LastSigned = now.Add(time.Minute)
	disk2.Serial = 11
	mem2 := base.Clone()
	mem2.LastSigned = now.Add(2 * time.Minute)
	mem2.Serial = 12
	mem2.PendingPublication = true
	got2 := mergeZone(base, disk2, mem2)
	if got2.Serial != 12 || !got2.PendingPublication {
		t.Fatalf("memory's later signing must win and stay pending: %+v", got2)
	}
}

func TestMergeZone_PublicationConfirmationOnDisk(t *testing.T) {
	now := time.Now().UTC()
	base := baseZone(now)
	base.PendingPublication = true
	base.PublishedAt, base.PublishedGenerationSignedAt = time.Time{}, time.Time{}

	// The CLI's hook confirmed the base generation; memory meanwhile signed a
	// newer generation (unsaved) that is itself pending.
	disk := base.Clone()
	disk.Revision = 4
	disk.ConfirmPublication(base.LastSigned, now.Add(10*time.Second))
	mem := base.Clone()
	mem.LastSigned = now.Add(time.Minute)
	mem.PendingPublication = true

	got := mergeZone(base, disk, mem)
	if !got.PublishedGenerationSignedAt.Equal(base.LastSigned) || got.PublishedAt.IsZero() {
		t.Fatalf("the disk's confirmation of the base generation must be adopted: %+v", got)
	}
	if !got.PendingPublication {
		t.Fatal("memory's newer generation is still unconfirmed and must remain pending")
	}
	if !got.LastSigned.Equal(mem.LastSigned) {
		t.Fatal("memory's newer signing must be kept")
	}
	if got.DNSKEYCacheHorizon.Before(disk.DNSKEYCacheHorizon) {
		t.Fatal("cache horizons are never lowered")
	}
}

func TestMergeZone_RolloverTimestampFromCLIAndForceResign(t *testing.T) {
	now := time.Now().UTC()
	base := baseZone(now)
	base.Rollover = &RolloverState{Type: "ksk", State: KSKRolloverStateDSAddWait, OldKeyID: 1, NewKeyID: 3, Started: now, Action: "add DS"}
	base.KSK = &KeyState{ID: 3, Algorithm: "ED25519"}

	// CLI `rollover complete`: only rollover metadata changed on disk.
	disk := base.Clone()
	disk.Revision = 4
	disk.Rollover.State = KSKRolloverStateDSPropagation
	disk.Rollover.DSObservedAt = now.Add(time.Minute)
	disk.Rollover.ParentDSTTL = 3600
	disk.Rollover.Action = "wait"
	// Daemon: signed (unsaved), rollover untouched.
	mem := base.Clone()
	mem.LastSigned = now.Add(30 * time.Second)

	got := mergeZone(base, disk, mem)
	if got.Rollover == nil || got.Rollover.State != KSKRolloverStateDSPropagation || !got.Rollover.DSObservedAt.Equal(disk.Rollover.DSObservedAt) || got.Rollover.Action != "wait" {
		t.Fatalf("the CLI's rollover metadata must be adopted: %+v", got.Rollover)
	}
	if !got.LastSigned.Equal(mem.LastSigned) {
		t.Fatal("the daemon's unsaved signing must be kept")
	}
	if got.ForceResign {
		t.Fatal("no key conflict: ForceResign must not be forced")
	}

	// Both sides transitioned the rollover: the disk's record wins and the
	// zone is re-signed against it.
	mem2 := base.Clone()
	mem2.Rollover.State = KSKRolloverStateRetiring
	mem2.LastSigned = now.Add(30 * time.Second)
	got2 := mergeZone(base, disk, mem2)
	if got2.Rollover.State != KSKRolloverStateDSPropagation || !got2.ForceResign {
		t.Fatalf("a rollover conflict must adopt the disk record and force a re-sign: %+v force=%v", got2.Rollover, got2.ForceResign)
	}
}

func TestMergeZone_ForceResignSetByEitherSide(t *testing.T) {
	now := time.Now().UTC()
	base := baseZone(now)
	disk := base.Clone()
	disk.Revision = 4
	disk.ForceResign = true
	mem := base.Clone()
	mem.Warnings = nil
	if got := mergeZone(base, disk, mem); !got.ForceResign {
		t.Fatal("a disk-side ForceResign must survive memory's unrelated change")
	}
	base2 := baseZone(now)
	base2.ForceResign = true
	disk2 := base2.Clone()
	disk2.Revision = 4
	disk2.Warnings = append(disk2.Warnings, "URGENT: x")
	mem2 := base2.Clone()
	mem2.ForceResign = false // memory signed
	mem2.LastSigned = now.Add(time.Minute)
	if got := mergeZone(base2, disk2, mem2); got.ForceResign {
		t.Fatal("memory cleared ForceResign by signing and the disk did not touch it: it stays cleared")
	}
}

// End to end through files: save, diverge, merge, save; then an old
// revisionless document.
func TestReloadFromDisk_ThreeWayThroughFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC()

	daemon := NewState(path)
	daemon.SetZone("a.", baseZone(now))
	daemon.Zones["a."].Revision = 0
	if err := daemon.Save(); err != nil {
		t.Fatal(err)
	}
	if daemon.GetZone("a.").Revision != 1 || daemon.BaseRevision("a.") != 1 {
		t.Fatalf("first save must set revision 1 and synchronize the base, got %d/%d", daemon.GetZone("a.").Revision, daemon.BaseRevision("a."))
	}

	// The daemon signs in memory; its save fails (unwritable path).
	daemon.UpdateZone("a.", func(z *ZoneState) {
		z.LastSigned = now.Add(time.Minute)
		z.Serial = 11
		z.ClearOperationError(OpSigning)
	})
	daemon.SetPath(filepath.Join(t.TempDir(), "missing-dir", "state.json"))
	if err := daemon.Save(); err == nil {
		t.Fatal("save into a missing directory must fail")
	}
	daemon.SetPath(path)

	// A CLI loads the disk, records an urgent warning and a rollover
	// timestamp, and saves.
	cli, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	cli.UpdateZone("a.", func(z *ZoneState) {
		z.AddWarning("URGENT: registrar left zone with ZERO DS")
		z.SetOperationError(OpRegistrar, "push failed")
	})
	if err := cli.Save(); err != nil {
		t.Fatal(err)
	}
	if cli.GetZone("a.").Revision != 2 {
		t.Fatalf("the CLI's save must advance the revision to 2, got %d", cli.GetZone("a.").Revision)
	}

	// The daemon's next cycle merges and saves.
	if err := daemon.ReloadFromDisk(); err != nil {
		t.Fatal(err)
	}
	z := daemon.GetZone("a.")
	if z.Serial != 11 || !z.LastSigned.Equal(now.Add(time.Minute)) {
		t.Fatalf("unsaved daemon signing lost in merge: %+v", z)
	}
	if !contains(z.Warnings, "URGENT: registrar left zone with ZERO DS") {
		t.Fatalf("CLI warning lost in merge: %v", z.Warnings)
	}
	if !z.HasOperationError(OpRegistrar) || z.HasOperationError(OpSigning) {
		t.Fatalf("errors must merge per operation (registrar added by CLI, signing cleared by daemon): %v", z.Errors)
	}
	if err := daemon.Save(); err != nil {
		t.Fatal(err)
	}
	disk, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	dz := disk.GetZone("a.")
	if dz.Revision <= 2 {
		t.Fatalf("the merged save must advance past the CLI's revision, got %d", dz.Revision)
	}
	if dz.Serial != 11 || !contains(dz.Warnings, "URGENT: registrar left zone with ZERO DS") || !dz.HasOperationError(OpRegistrar) {
		t.Fatalf("both sides must be on disk: %+v", dz)
	}

	// The CLI now clears the warning; the daemon (clean) adopts the removal
	// and its later save does not resurrect it.
	cli2, _ := LoadState(path)
	cli2.UpdateZone("a.", func(z *ZoneState) { z.ClearStickyWarnings() })
	if err := cli2.Save(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.ReloadFromDisk(); err != nil {
		t.Fatal(err)
	}
	if contains(daemon.GetZone("a.").Warnings, "URGENT: registrar left zone with ZERO DS") {
		t.Fatal("a warning cleared by the CLI must not survive the merge")
	}
	if err := daemon.Save(); err != nil {
		t.Fatal(err)
	}
	disk2, _ := LoadState(path)
	if contains(disk2.GetZone("a.").Warnings, "URGENT") {
		t.Fatal("a cleared warning was resurrected by the daemon's save")
	}
}

// A zone the disk lost since the last synchronization (no removal marker) is
// dropped only when memory holds nothing unsaved for it; a zone removed
// through a marker follows the marker as before.
func TestReloadFromDisk_ZoneRemovalAndReAddition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC()
	daemon := NewState(path)
	daemon.SetZone("a.", baseZone(now))
	daemon.SetZone("b.", baseZone(now))
	if err := daemon.Save(); err != nil {
		t.Fatal(err)
	}

	cli, _ := LoadState(path)
	cli.MarkRemoved("a.")
	if err := cli.Save(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.ReloadFromDisk(); err != nil {
		t.Fatal(err)
	}
	if daemon.GetZone("a.") != nil {
		t.Fatal("a zone removed by the CLI must be dropped")
	}
	if _, ok := daemon.RemovedAt("a."); !ok {
		t.Fatal("the removal marker must be adopted")
	}

	// Re-added by a CLI `add` (fresh record), while memory never held it.
	cli2, _ := LoadState(path)
	cli2.ClearRemoved("a.")
	fresh := baseZone(now.Add(time.Hour))
	fresh.Revision = 0
	cli2.SetZone("a.", fresh)
	if err := cli2.Save(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.ReloadFromDisk(); err != nil {
		t.Fatal(err)
	}
	if z := daemon.GetZone("a."); z == nil || !z.LastSigned.Equal(now.Add(time.Hour)) {
		t.Fatalf("the re-added zone must be adopted: %+v", z)
	}
	if _, ok := daemon.RemovedAt("a."); ok {
		t.Fatal("re-adding clears the marker")
	}
}

// Documents written before the revision existed load at revision 0 and
// merge by content.
func TestReloadFromDisk_RevisionlessDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	old := `{"zones":{"a.":{"path":"/z/a.zone","serial":5,"last_signed":"2024-01-01T00:00:00Z","signatures_expire":"2024-01-15T00:00:00Z","ksk":{"id":1,"algorithm":"ED25519","created":"2024-01-01T00:00:00Z","expires":"2029-01-01T00:00:00Z"},"zsk":{"id":2,"algorithm":"ED25519","created":"2024-01-01T00:00:00Z","expires":"2024-04-01T00:00:00Z"},"warnings":["w0"]}}}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	daemon, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if daemon.GetZone("a.").Revision != 0 || daemon.BaseRevision("a.") != 0 {
		t.Fatal("an old document loads at revision 0")
	}
	// A CLI (also revision-unaware in its saved output? no: the CLI is this
	// version) adds a warning.
	cli, _ := LoadState(path)
	cli.UpdateZone("a.", func(z *ZoneState) { z.AddWarning("URGENT: x") })
	if err := cli.Save(); err != nil {
		t.Fatal(err)
	}
	// Daemon has unsaved signing.
	daemon.UpdateZone("a.", func(z *ZoneState) { z.Serial = 6; z.LastSigned = time.Now().UTC() })
	if err := daemon.ReloadFromDisk(); err != nil {
		t.Fatal(err)
	}
	z := daemon.GetZone("a.")
	if z.Serial != 6 || !contains(z.Warnings, "URGENT: x") || !contains(z.Warnings, "w0") {
		t.Fatalf("content merge against a revisionless base must keep both sides: %+v", z)
	}
	if err := daemon.Save(); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Zones map[string]struct {
			Revision uint64 `json:"revision"`
		} `json:"zones"`
	}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Zones["a."].Revision < 2 {
		t.Fatalf("the saved document must carry a revision past the CLI's (1), got %d", doc.Zones["a."].Revision)
	}
}

// Independent creation on both sides adopts the disk copy.
func TestReloadFromDisk_IndependentCreationAdoptsDisk(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC()
	daemon := NewState(path)
	if err := daemon.Save(); err != nil {
		t.Fatal(err)
	}
	memZone := baseZone(now)
	memZone.KSK.ID = 100
	daemon.SetZone("a.", memZone)

	cli, _ := LoadState(path)
	diskZone := baseZone(now.Add(time.Second))
	diskZone.KSK.ID = 200
	cli.SetZone("a.", diskZone)
	if err := cli.Save(); err != nil {
		t.Fatal(err)
	}
	if err := daemon.ReloadFromDisk(); err != nil {
		t.Fatal(err)
	}
	if daemon.GetZone("a.").KSK.ID != 200 {
		t.Fatal("a zone created independently on disk (with its key files committed) must win")
	}
}

func TestSave_RevisionMonotonicAcrossFailedSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s := NewState(path)
	s.SetZone("a.", baseZone(time.Now().UTC()))
	s.Zones["a."].Revision = 0
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	r1 := s.GetZone("a.").Revision
	// Unchanged content: another save does not bump.
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if s.GetZone("a.").Revision != r1 {
		t.Fatal("an unchanged zone must keep its revision")
	}
	s.UpdateZone("a.", func(z *ZoneState) { z.Serial++ })
	s.SetPath(filepath.Join(t.TempDir(), "nope", "state.json"))
	_ = s.Save() // fails
	s.SetPath(path)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if got := s.GetZone("a.").Revision; got <= r1 {
		t.Fatalf("a changed zone must advance its revision, got %d (was %d)", got, r1)
	}
	loaded, _ := LoadState(path)
	if loaded.GetZone("a.").Revision != s.GetZone("a.").Revision {
		t.Fatal("the persisted revision must equal the in-memory one after a committed save")
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s || (len(s) < len(x) && x[:len(s)] == s) {
			return true
		}
	}
	return false
}
