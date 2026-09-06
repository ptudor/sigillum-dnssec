package main

import (
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// canonicalConflict reports whether domain canonically matches (case- and
// trailing-dot-insensitively) any zone already present in the config or state,
// other than an exact match (which callers check separately). Returns the
// conflicting existing name (R-029).
func canonicalConflict(cfg *config.Config, state *statepkg.State, domain string) (string, bool) {
	id := config.CanonicalZoneIdentity(domain)
	for existing := range cfg.Zones {
		if existing != domain && config.CanonicalZoneIdentity(existing) == id {
			return existing, true
		}
	}
	for _, existing := range state.ZoneNames() {
		if existing != domain && config.CanonicalZoneIdentity(existing) == id {
			return existing, true
		}
	}
	return "", false
}
