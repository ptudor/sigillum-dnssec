package validator

import "testing"

// R-051: registrable-domain detection uses the public suffix list, not a
// two-label heuristic — so multi-label public suffixes (co.uk) work.
func TestR051_RegistrableDomainPublicSuffix(t *testing.T) {
	reg := map[string]string{
		"example.com":       "example.com.",
		"www.example.com":   "example.com.",
		"example.co.uk":     "example.co.uk.",
		"www.example.co.uk": "example.co.uk.",
		"example.com.au":    "example.com.au.",
	}
	for in, want := range reg {
		if got := GetRegistrableDomain(in); got != want {
			t.Errorf("GetRegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}

	// Names that are themselves registrable (RDAP should run).
	for _, z := range []string{"example.com", "example.co.uk", "example.com.au"} {
		if !IsRegistrableDomain(z) {
			t.Errorf("IsRegistrableDomain(%q) = false, want true", z)
		}
	}
	// Names that are NOT the registrable domain (RDAP must NOT run).
	for _, z := range []string{"www.example.com", "co.uk", "com", ".", "www.example.co.uk"} {
		if IsRegistrableDomain(z) {
			t.Errorf("IsRegistrableDomain(%q) = true, want false", z)
		}
	}
}
