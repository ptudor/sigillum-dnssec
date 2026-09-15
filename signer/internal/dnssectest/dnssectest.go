// Package dnssectest provides test fixtures shared across the signer's
// package-level test suites (root, internal/signer, …). It lives in a real
// (non _test.go) package so both the root package's tests and the internal
// packages' white-box tests can import the same fixtures without duplicating
// them; only test binaries import it.
package dnssectest

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
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

// WriteBindKeyPair writes a K<owner>.+<alg>+<tag>.{key,private} pair into dir
// the way dnssec-keygen and ldns-keygen do (comment header on the public
// half, BIND private-key fields plus Created/Publish/Activate timestamps on
// the private half) and returns the DNSKEY and the pair's base path. RSA
// keys are 2048 bits.
func WriteBindKeyPair(t *testing.T, dir, owner string, alg uint8, flags uint16, created time.Time) (*dns.DNSKEY, string) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: alg,
	}
	bits := 256
	switch alg {
	case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		bits = 2048
	case dns.ECDSAP384SHA384:
		bits = 384
	}
	priv, err := k.Generate(bits)
	if err != nil {
		t.Fatal(err)
	}
	stamp := created.UTC().Format("20060102150405")
	base := filepath.Join(dir, fmt.Sprintf("K%s+%03d+%05d", dns.Fqdn(owner), alg, k.KeyTag()))
	keyFile := fmt.Sprintf("; This is a key, keyid %d, for %s\n; Created: %s (%s)\n%s\n",
		k.KeyTag(), dns.Fqdn(owner), stamp, created.UTC().Format(time.ANSIC), k.String())
	privFile := k.PrivateKeyString(priv) + "Created: " + stamp + "\nPublish: " + stamp + "\nActivate: " + stamp + "\n"
	if err := os.WriteFile(base+".key", []byte(keyFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".private", []byte(privFile), 0o600); err != nil {
		t.Fatal(err)
	}
	return k, base
}
