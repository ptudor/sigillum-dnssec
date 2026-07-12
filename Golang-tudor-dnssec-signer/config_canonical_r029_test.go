package main

import "testing"

// R-029: canonical identity normalizes case and a trailing root dot.
func TestR029_CanonicalZoneIdentity(t *testing.T) {
	same := [][2]string{
		{"example.com", "Example.COM"},
		{"example.com", "example.com."},
		{"EXAMPLE.COM.", "example.com"},
	}
	for _, p := range same {
		if canonicalZoneIdentity(p[0]) != canonicalZoneIdentity(p[1]) {
			t.Errorf("%q and %q should share a canonical identity", p[0], p[1])
		}
	}
	if canonicalZoneIdentity("a.example.com") == canonicalZoneIdentity("b.example.com") {
		t.Error("distinct zones must not share an identity")
	}
}

// R-029: a config with two entries that denote the same DNS zone is rejected
// before any signing/registrar action.
func TestR029_ValidateRejectsDuplicateCanonicalZones(t *testing.T) {
	mk := func(a, b string) *Config {
		c := DefaultConfig()
		c.Zones = map[string]ZoneConfig{a: {Path: "/a"}, b: {Path: "/b"}}
		return c
	}
	if err := mk("example.com", "Example.COM").Validate(); err == nil {
		t.Error("case-variant duplicate zones must be rejected")
	}
	if err := mk("example.com", "example.com.").Validate(); err == nil {
		t.Error("trailing-dot duplicate zones must be rejected")
	}

	// A single canonical entry validates.
	c := DefaultConfig()
	c.Zones = map[string]ZoneConfig{"example.com": {Path: "/a"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("single canonical zone must validate: %v", err)
	}
}
