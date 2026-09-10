package signer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-029 accepts case variants of valid managed-zone names. NSEC3
// owners must use that zone's canonical wire identity so a mixed-case
// management spelling can be signed and pass the post-sign verification gate.
func TestSignZone_MixedCaseManagedNameNSEC3(t *testing.T) {
	const domain = "Example.COM"
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	cfg.DNSSEC.NSECVersion = "nsec3"
	zonePath := filepath.Join(dataDir, domain+".zone")
	zoneText := strings.ReplaceAll(baseZone, "example.com", domain)
	if err := os.WriteFile(zonePath, []byte(zoneText), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}
	for _, dir := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := EnsureDir(dir); err != nil {
			t.Fatal(err)
		}
	}

	kg := NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	st := statepkg.NewState(cfg.StatePath())
	st.SetZone(domain, &statepkg.ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})
	s := NewSigner(cfg, st)
	if err := s.SignZone(domain); err != nil {
		t.Fatalf("mixed-case managed zone failed NSEC3 signing: %v", err)
	}

	apex := canonicalName(domain)
	for _, rr := range parseSigned(t, s.OutputPath(domain), domain) {
		switch rr.(type) {
		case *dns.NSEC3PARAM:
			if rr.Header().Name != apex {
				t.Fatalf("NSEC3PARAM owner %q, want canonical apex %q", rr.Header().Name, apex)
			}
		case *dns.NSEC3:
			labels := dns.SplitDomainName(rr.Header().Name)
			gotApex := strings.Join(labels[1:], ".") + "."
			if gotApex != apex {
				t.Fatalf("NSEC3 owner %q has apex %q, want canonical apex %q", rr.Header().Name, gotApex, apex)
			}
		}
	}
}
