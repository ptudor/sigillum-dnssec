package main

import (
	"bytes"
	"strings"
	"testing"
)

// R-023: hook stderr capture is bounded (a runaway hook cannot exhaust memory) and
// always drains the pipe fully (a full pipe must not deadlock the child).
func TestR023_CappedBuffer(t *testing.T) {
	cb := &cappedBuffer{max: 100}

	big := bytes.Repeat([]byte("x"), 1_000_000)
	n, err := cb.Write(big)
	if err != nil || n != len(big) {
		t.Fatalf("Write must report the FULL length so the pipe keeps draining: n=%d err=%v", n, err)
	}

	s := cb.String()
	if len(s) > 100+len("\n[stderr truncated]") {
		t.Fatalf("retained %d bytes, expected ~100 (cap) plus the marker", len(s))
	}
	if !strings.Contains(s, "[stderr truncated]") {
		t.Error("truncation marker missing after overflow")
	}

	// Subsequent writes past the cap still drain fully and stay truncated.
	if n, _ := cb.Write([]byte("more")); n != 4 {
		t.Fatalf("second write must drain fully: n=%d", n)
	}

	// A small write within the cap is retained verbatim (no marker).
	cb2 := &cappedBuffer{max: 100}
	cb2.Write([]byte("hello"))
	if cb2.String() != "hello" {
		t.Fatalf("within-cap capture = %q, want %q", cb2.String(), "hello")
	}
}
