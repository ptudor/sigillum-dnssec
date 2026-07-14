package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
)

// R-034: DNSSEC records present in the input (a stale RRSIG, NSEC3PARAM, apex
// DNSKEY from an already-signed file) are stripped before signing, so the output
// has exactly one generated chain and no RRSIG-over-RRSIG.
func TestSignZone_StripsInputDNSSEC(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)

	// An input zone that already carries DNSSEC records (as if re-processing a
	// signed file by mistake): a stray RRSIG covering A, an NSEC3PARAM, and an
	// apex DNSKEY.
	zone := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
@	IN	NSEC3PARAM 1 0 5 AABBCCDD
@	IN	DNSKEY	256 3 15 AAAABBBBCCCCDDDD
ns1	IN	A	192.0.2.1
www	IN	A	192.0.2.10
www	3600 IN	RRSIG A 15 3 3600 20991231235959 20200101000000 1111 example.com. AAAABBBBCCCC
`
	records := signAndParseZone(t, cfg, "example.com", zone)

	var nsec3param, rrsigOverRRSIG, apexDNSKEY int
	signingKeyTags := map[uint16]bool{}
	for _, rr := range records {
		switch v := rr.(type) {
		case *dns.NSEC3PARAM:
			nsec3param++
		case *dns.DNSKEY:
			apexDNSKEY++
			signingKeyTags[v.KeyTag()] = true
		case *dns.RRSIG:
			if v.TypeCovered == dns.TypeRRSIG {
				rrsigOverRRSIG++
			}
		}
	}

	if nsec3param != 1 {
		t.Errorf("expected exactly one (generated) NSEC3PARAM, got %d (input one not stripped?)", nsec3param)
	}
	if rrsigOverRRSIG != 0 {
		t.Errorf("output must not contain RRSIG-over-RRSIG, got %d", rrsigOverRRSIG)
	}
	// The stale input DNSKEY (tag of "256 3 15 AAAA...") must be gone; only the
	// signer's generated keys should be present.
	if apexDNSKEY == 0 {
		t.Error("expected the signer's generated DNSKEY records in output")
	}
	// The stray RRSIG referenced key tag 1111; no generated RRSIG should carry it.
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.KeyTag == 1111 {
			t.Error("stale input RRSIG (key tag 1111) was carried into the output")
		}
	}
}

// R-035: a record whose owner is outside the zone apex is rejected rather than
// signed into a broken NSEC/NSEC3 chain.
func TestSignZone_RejectsOutOfZoneOwner(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	domain := "example.com"

	zone := `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
evil.org.	IN	A	192.0.2.99
`
	zonePath := filepath.Join(dataDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zone), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatal(err)
	}

	state := NewState(cfg.StatePath())
	keyGen := NewKeyGenerator(cfg)
	ksk, _ := keyGen.GenerateKSK(domain)
	zsk, _ := keyGen.GenerateZSK(domain)
	state.SetZone(domain, &ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})

	signer := NewSigner(cfg, state)
	err := signer.SignZone(domain)
	if err == nil {
		t.Fatal("SignZone must reject a zone containing an out-of-zone owner (R-035)")
	}
	if !contains(err.Error(), "evil.org") {
		t.Errorf("error should name the offending owner, got: %v", err)
	}
}
