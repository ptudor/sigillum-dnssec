// Package dnssectest provides test fixtures shared across the signer's
// package-level test suites (root, internal/signer, …). It lives in a real
// (non _test.go) package so both the root package's tests and the internal
// packages' white-box tests can import the same fixtures without duplicating
// them; only test binaries import it.
package dnssectest

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
)

// Config returns a fast, in-tempdir *config.Config suitable for signing tests:
// short lifetimes/validities so rollover and refresh paths trigger quickly, and
// loopback-only web/health listeners. dataDir roots the signed/keys/state tree.
func Config(t *testing.T, dataDir string) *config.Config {
	t.Helper()
	return &config.Config{
		OutputDir:    filepath.Join(dataDir, "signed"),
		DataDir:      dataDir,
		PollInterval: config.Duration{Duration: 1 * time.Second},
		DNSSEC: config.DNSSECConfig{
			Algorithm:          "ED25519",
			KSKLifetime:        config.Duration{Duration: 10 * time.Second},
			ZSKLifetime:        config.Duration{Duration: 5 * time.Second},
			SignatureValidity:  config.Duration{Duration: 3 * time.Second},
			SignatureRefresh:   config.Duration{Duration: 1 * time.Second},
			NSECVersion:        "nsec3",
			NSEC3Iterations:    0,
			NSEC3Salt:          "",
			DNSKEYTtl:          3600,
			RolloverPrepublish: config.Duration{Duration: 2 * time.Second},
			RolloverSwitch:     config.Duration{Duration: 1 * time.Second},
		},
		Web: config.WebConfig{
			Enabled: false,
			Listen:  "127.0.0.1:8053",
		},
		Health: config.HealthConfig{
			Listen: "127.0.0.1:8054",
		},
		Zones: make(map[string]config.ZoneConfig),
		Hooks: config.HooksConfig{},
	}
}
