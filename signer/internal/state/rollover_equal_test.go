package state

import "testing"

func TestRolloverEqual(t *testing.T) {
	a := &RolloverState{Type: "ksk", State: "ds_add_wait", OldKeyID: 1, NewKeyID: 2}
	b := &RolloverState{Type: "ksk", State: "ds_add_wait", OldKeyID: 1, NewKeyID: 2}
	if !rolloverEqual(a, b) {
		t.Fatal("identical rollovers must be equal")
	}
	if rolloverEqual(a, nil) {
		t.Fatal("nil vs non-nil must not be equal")
	}
	if !rolloverEqual(nil, nil) {
		t.Fatal("nil == nil")
	}
	if rolloverEqual(a, &RolloverState{Type: "zsk"}) {
		t.Fatal("different type must not be equal")
	}
}
