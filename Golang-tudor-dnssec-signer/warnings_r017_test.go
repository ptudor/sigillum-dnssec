package main

import (
	"strings"
	"testing"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// R-017: a routine sign/rollover clear (ClearTransientWarnings) must preserve a
// sticky registrar-critical "URGENT:" warning, and only a resolving operation
// (ClearStickyWarnings) removes it.
func TestR017_StickyWarningsSurviveTransientClear(t *testing.T) {
	z := &statepkg.ZoneState{}
	z.AddWarning("URGENT: registrar left zone with ZERO DS at parent; re-run push")
	z.AddWarning("ZSK expires in 3 days (will auto-rollover)")
	z.AddWarning("KSK rollover due - run 'dnssec-tudor rollover start example.com'")

	// A successful sign refreshes transient notices but must keep the URGENT one.
	z.ClearTransientWarnings()
	if len(z.Warnings) != 1 || !strings.HasPrefix(z.Warnings[0], "URGENT:") {
		t.Fatalf("ClearTransientWarnings must preserve the URGENT warning, got %v", z.Warnings)
	}

	// A confirmed registrar read-back resolves and clears the sticky warning.
	z.ClearStickyWarnings()
	if len(z.Warnings) != 0 {
		t.Fatalf("ClearStickyWarnings must remove the URGENT warning, got %v", z.Warnings)
	}
}

// R-017: transient clear with no sticky warnings still clears everything.
func TestR017_TransientClearWithoutSticky(t *testing.T) {
	z := &statepkg.ZoneState{}
	z.AddWarning("ZSK expires in 3 days (will auto-rollover)")
	z.ClearTransientWarnings()
	if len(z.Warnings) != 0 {
		t.Fatalf("transient warnings should all clear when none are sticky, got %v", z.Warnings)
	}
}
