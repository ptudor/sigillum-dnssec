package validator

import "testing"

// R-040: RRSIG signer-name comparison is DNS-aware case-insensitive exact match.
func TestR040_LeafSignerMatchesZone(t *testing.T) {
	match := []struct{ signer, zone string }{
		{"example.com.", "example.com."},
		{"EXAMPLE.com.", "example.com."},
		{"example.com", "example.com."},  // missing trailing dot
		{"Example.COM.", "eXaMpLe.com."}, // mixed case both sides
	}
	for _, c := range match {
		if !leafSignerMatchesZone(c.signer, c.zone) {
			t.Errorf("leafSignerMatchesZone(%q,%q) = false, want true", c.signer, c.zone)
		}
	}

	noMatch := []struct{ signer, zone string }{
		{"other.com.", "example.com."},
		{"notexample.com.", "example.com."},  // deceptive suffix
		{"sub.example.com.", "example.com."}, // subdomain, not exact
	}
	for _, c := range noMatch {
		if leafSignerMatchesZone(c.signer, c.zone) {
			t.Errorf("leafSignerMatchesZone(%q,%q) = true, want false", c.signer, c.zone)
		}
	}
}
