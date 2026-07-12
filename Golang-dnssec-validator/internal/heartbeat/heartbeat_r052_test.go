package heartbeat

import "testing"

// R-052: the background heartbeat status is "running" while validations are in
// flight (tracked by the active-validation count the handlers maintain) and "idle"
// otherwise — instead of always idle because no caller ever set a "validate:" action.
func TestR052_PeriodicActionTracksActiveValidations(t *testing.T) {
	c := &Client{enabled: true}

	if got := c.periodicAction(); got != "idle" {
		t.Fatalf("no active validations: action = %q, want idle", got)
	}

	c.ValidationStarted()
	c.ValidationStarted()
	if got := c.periodicAction(); got != "running" {
		t.Fatalf("two active validations: action = %q, want running", got)
	}

	c.ValidationFinished()
	if got := c.periodicAction(); got != "running" {
		t.Fatalf("one still active: action = %q, want running", got)
	}

	c.ValidationFinished()
	if got := c.periodicAction(); got != "idle" {
		t.Fatalf("all finished: action = %q, want idle", got)
	}
}
