//go:build !windows

package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/registrar"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RM51X-001: the parent's DS set may change only after the DNSKEY RRset
// carrying the new key(s) has propagated to every authoritative server and
// out of resolver caches (RFC 6781 §4.1.2 / §4.1.4). Before the fix the old
// DS was removed at `rollover complete` and the new-algorithm DS was added
// at `rollover algorithm`, both seconds after the keys were written.

// A KSK rollover keeps old+new at the registrar through completion, installs
// new-only once the new DNSKEY RRset has propagated, retries a failed
// registrar update every cycle, and does not end before that update
// succeeded — even once the retired zone is served.
func TestRM51X001_KSKOldDSRemovedOnlyAfterPropagationAndRetriedUntilDone(t *testing.T) {
	lab := newRegistrarLab(t)
	oldTag := lab.state.GetZone(lab.domain).KSK.ID
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "add")
	rm := newRolloverManager(lab.cfg, lab.state)
	if err := rm.StartKSKRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "rollover_start")
	zs := lab.state.GetZone(lab.domain)
	newTag := zs.Rollover.NewKeyID
	both := strings.Join(tagStrings(oldTag, newTag), ",")

	// The new DS was observed at every parent server two seconds ago with a
	// one-second DS TTL: the old KSK may retire, but the old DS must stay.
	if err := rm.CompleteKSKRollover(lab.domain, time.Now().Add(-2*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	if !registrar.IncludesOldDS(zs.Rollover) {
		t.Fatal("before propagation the phase-correct DS set still includes the old DS")
	}
	if !strings.Contains(zs.Rollover.Action, "do NOT remove the OLD DS") {
		t.Fatalf("the operator must be told to keep the old DS: %q", zs.Rollover.Action)
	}
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "rollover_complete")
	if got := lab.fake.tags(); strings.Join(got, ",") != both {
		t.Fatalf("completion before propagation keeps old+new, got %v", got)
	}
	if err := RunRegistrarPush(nil, []string{lab.domain}); err != nil {
		t.Fatal(err)
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != both {
		t.Fatalf("an explicit push before propagation keeps old+new, got %v", got)
	}

	// The DS TTL has elapsed: the old KSK retires, but with the registrar
	// failing the parent keeps old+new and the failure is visible.
	lab.fake.setFailPuts(true)
	lab.propagateNewKeys(t, rm.CheckKSKRollover)
	if err := rm.CheckKSKRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover == nil || zs.Rollover.State != statepkg.KSKRolloverStateRetiring {
		t.Fatalf("after the DS TTL the old KSK retires regardless of the registrar: %+v", zs.Rollover)
	}
	if !zs.Rollover.DSRemovalPushedAt.IsZero() || strings.Join(lab.fake.tags(), ",") != both {
		t.Fatalf("a failed update must not be recorded or applied: pushed=%v registrar=%v", zs.Rollover.DSRemovalPushedAt, lab.fake.tags())
	}
	if !strings.Contains(strings.Join(zs.Warnings, "\n"), "registrar auto-publish failed") {
		t.Fatalf("the failure must be a visible zone warning: %v", zs.Warnings)
	}

	// The retired generation is confirmed served, yet the rollover must not
	// end while the parent still owes the new-only set.
	lab.state.Mutate(func() {
		now := time.Now().UTC()
		zs.ConfirmPublication(now, now)
	})
	if err := rm.CheckKSKRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover == nil {
		t.Fatal("the rollover must not end before the registrar holds the new-only set")
	}
	if !registrar.IncludesOldDS(zs.Rollover) == false {
		t.Fatal("once propagated, the phase-correct set is new-only")
	}

	// Healed: the next check installs new-only exactly once and completes.
	lab.fake.setFailPuts(false)
	if err := rm.CheckKSKRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != fmt.Sprintf("%d", newTag) {
		t.Fatalf("after healing the registrar holds new-only, got %v", got)
	}
	if _, deletes := lab.fake.counts(); deletes != 1 {
		t.Fatalf("exactly one replace, got %d DELETEs", deletes)
	}
	if lab.state.GetZone(lab.domain).Rollover != nil {
		t.Fatal("the rollover ends once the retired zone is served and the parent holds the new-only set")
	}
}

// Without registrar automation nothing is pushed, but the rollover record
// (and its advice about the old DS) persists until the new DNSKEY RRset has
// propagated; it ends once the retired zone is served and that horizon has
// passed.
func TestRM51X001_KSKWithoutAutomationEndsAfterRetirementAndPropagation(t *testing.T) {
	lab := newRegistrarLab(t)
	lab.cfg.Registrar.Dynadot.AutoPublish = false
	rm := newRolloverManager(lab.cfg, lab.state)
	if err := rm.StartKSKRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if err := rm.CompleteKSKRollover(lab.domain, time.Now().Add(-2*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	zs := lab.state.GetZone(lab.domain)
	if err := rm.CheckKSKRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover.State != statepkg.KSKRolloverStateRetiring {
		t.Fatalf("expected retiring, got %q", zs.Rollover.State)
	}
	if !strings.Contains(zs.Rollover.Action, "do NOT remove the OLD DS") {
		t.Fatalf("the retiring record must still advise on the old DS: %q", zs.Rollover.Action)
	}
	lab.propagateNewKeys(t, rm.CheckKSKRollover)
	if zs.Rollover == nil {
		t.Fatal("the record persists until the propagation horizon has passed")
	}
	if err := rm.CheckKSKRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if lab.state.GetZone(lab.domain).Rollover != nil {
		t.Fatal("with no automation the rollover ends once the retired zone is served and the new keys have propagated")
	}
	if _, deletes := lab.fake.counts(); deletes != 0 {
		t.Fatalf("no registrar update without automation, got %d DELETEs", deletes)
	}
}

// An algorithm rollover publishes nothing at start; status says so and is
// not action_required; once the new keys and signatures have propagated the
// DS is added exactly once and the operator is asked to complete.
func TestRM51X001_AlgorithmNewDSAddedOnlyAfterPropagation(t *testing.T) {
	lab := newRegistrarLab(t)
	oldTag := lab.state.GetZone(lab.domain).KSK.ID
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "add")
	rm := newRolloverManager(lab.cfg, lab.state)
	if err := rm.StartAlgorithmRollover(lab.domain, "ECDSAP256SHA256"); err != nil {
		t.Fatal(err)
	}
	zs := lab.state.GetZone(lab.domain)
	newTag := zs.Rollover.NewKeyID
	for i := 0; i < 2; i++ {
		if err := rm.CheckAlgorithmRollover(lab.domain); err != nil {
			t.Fatal(err)
		}
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != fmt.Sprintf("%d", oldTag) {
		t.Fatalf("no new DS before propagation, got %v", got)
	}
	if zs.Rollover.NeedsOperator() || zs.Status() != "warning" {
		t.Fatalf("the automatic wait is not action_required: needsOperator=%v status=%q", zs.Rollover.NeedsOperator(), zs.Status())
	}
	if !strings.Contains(zs.Rollover.Action, "do NOT publish the new DS yet") {
		t.Fatalf("the operator must be told to wait: %q", zs.Rollover.Action)
	}

	lab.propagateNewKeys(t, rm.CheckAlgorithmRollover)
	if err := rm.CheckAlgorithmRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != strings.Join(tagStrings(oldTag, newTag), ",") {
		t.Fatalf("after propagation the new DS is added additively, got %v", got)
	}
	if zs.Rollover.DSAddPushedAt.IsZero() || !zs.Rollover.NeedsOperator() || !strings.Contains(zs.Rollover.Action, "rollover complete") {
		t.Fatalf("the add must be recorded and the operator asked to complete: %+v", zs.Rollover)
	}
	puts, deletes := lab.fake.counts()
	for i := 0; i < 3; i++ {
		if err := rm.CheckAlgorithmRollover(lab.domain); err != nil {
			t.Fatal(err)
		}
	}
	if p, d := lab.fake.counts(); p != puts || d != deletes {
		t.Fatalf("the add must not be repeated: PUTs %d→%d DELETEs %d→%d", puts, p, deletes, d)
	}
	disk, err := statepkg.LoadState(lab.cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if disk.GetZone(lab.domain).Rollover.DSAddPushedAt.IsZero() {
		t.Fatal("the add marker must be persisted")
	}
}
