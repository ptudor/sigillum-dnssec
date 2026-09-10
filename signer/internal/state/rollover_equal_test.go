package state

import (
	"testing"
	"time"
)

// rolloverStateEqual is the merge's rollover-class comparison (RDAYBLUEX-019):
// every persisted field counts, not only type/phase/key identities, so a
// CLI-side timestamp or action change is seen as a change.
func TestRolloverStateEqual(t *testing.T) {
	now := time.Now().UTC()
	a := &RolloverState{Type: "ksk", State: "ds_add_wait", OldKeyID: 1, NewKeyID: 2, Started: now, Action: "add DS"}
	b := &RolloverState{Type: "ksk", State: "ds_add_wait", OldKeyID: 1, NewKeyID: 2, Started: now, Action: "add DS"}
	if !rolloverStateEqual(a, b) {
		t.Fatal("identical rollovers must be equal")
	}
	if rolloverStateEqual(a, nil) {
		t.Fatal("nil vs non-nil must not be equal")
	}
	if !rolloverStateEqual(nil, nil) {
		t.Fatal("nil == nil")
	}
	if rolloverStateEqual(a, &RolloverState{Type: "zsk"}) {
		t.Fatal("different type must not be equal")
	}
	c := *a
	c.DSObservedAt = now.Add(time.Minute)
	if rolloverStateEqual(a, &c) {
		t.Fatal("a phase timestamp change must be a change")
	}
	d := *a
	d.Action = "remove old DS"
	if rolloverStateEqual(a, &d) {
		t.Fatal("an action change must be a change")
	}
	e := *a
	e.Started = now.Add(time.Nanosecond)
	if rolloverStateEqual(a, &e) {
		t.Fatal("a Started change must be a change")
	}
	// Equal instants in different locations are equal.
	f := *a
	f.Started = now.In(time.FixedZone("x", 3600))
	if !rolloverStateEqual(a, &f) {
		t.Fatal("equal instants must compare equal regardless of location")
	}
}
