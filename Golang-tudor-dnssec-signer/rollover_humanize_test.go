package main

import (
	"testing"
	"time"
)

// R-014: the pre-publish Action message is built from the configured switch
// duration, not a hardcoded "7 days".
func TestHumanizeRolloverDelay(t *testing.T) {
	if got := humanizeRolloverDelay(7 * 24 * time.Hour); got != "7 day(s)" {
		t.Errorf("7d = %q, want \"7 day(s)\"", got)
	}
	if got := humanizeRolloverDelay(10 * 24 * time.Hour); got != "10 day(s)" {
		t.Errorf("10d = %q, want \"10 day(s)\"", got)
	}
	if got := humanizeRolloverDelay(1 * time.Second); got != "1s" {
		t.Errorf("1s = %q, want \"1s\"", got)
	}
}
