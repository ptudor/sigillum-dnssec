package validator

import (
	"testing"

	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// R-043: only a zone key with protocol 3 that is not revoked may verify signatures.
func TestR043_EligibleForVerification(t *testing.T) {
	valid := dnspkg.DNSKEYRecord{Flags: 257, Protocol: 3, Algorithm: 8, PublicKey: "dGVzdA=="}
	if !valid.EligibleForVerification() {
		t.Error("a valid KSK (flags 257, protocol 3) must be eligible")
	}
	zsk := dnspkg.DNSKEYRecord{Flags: 256, Protocol: 3, Algorithm: 8}
	if !zsk.EligibleForVerification() {
		t.Error("a valid ZSK (flags 256) must be eligible")
	}

	bad := map[string]dnspkg.DNSKEYRecord{
		"protocol 2":         {Flags: 257, Protocol: 2, Algorithm: 8},
		"zone key flag clear": {Flags: 1, Protocol: 3, Algorithm: 8}, // SEP only, no Zone Key bit
		"flags zero":          {Flags: 0, Protocol: 3, Algorithm: 8},
		"revoke bit":          {Flags: 257 | 0x0080, Protocol: 3, Algorithm: 8},
		"IsRevoked":           {Flags: 257, Protocol: 3, Algorithm: 8, IsRevoked: true},
	}
	for name, k := range bad {
		if k.EligibleForVerification() {
			t.Errorf("%s: key must be ineligible for verification", name)
		}
	}
}

// R-044: the chain link must try EVERY eligible same-tag DNSKEY, not just the
// first in slice order, so a colliding key ordered before the real one does not
// hide a valid delegation.
func TestR044_ChainLinkTriesAllSameTagKeys(t *testing.T) {
	zone := "example.com."
	valid := dnspkg.DNSKEYRecord{KeyTag: 1234, Flags: 257, Protocol: 3, Algorithm: 8, PublicKey: "dGVzdFZhbGlkS2V5", IsKSK: true}
	decoy := dnspkg.DNSKEYRecord{KeyTag: 1234, Flags: 257, Protocol: 3, Algorithm: 8, PublicKey: "ZGVjb3lLZXlNYXQ=", IsKSK: true}
	digest, err := ComputeDSDigestFromDNSKEY(zone, valid, 2)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	ds := []dnspkg.DSRecord{{KeyTag: 1234, Algorithm: 8, DigestType: 2, Digest: digest}}

	// decoy first, valid second
	link, err := ValidateChainLink(ds, []dnspkg.DNSKEYRecord{decoy, valid}, zone)
	if err != nil || link == nil || !link.DSMatchesKSK {
		t.Fatalf("chain link must match the valid same-tag key regardless of order: err=%v link=%+v", err, link)
	}
}

// R-043: a key that matches the DS digest but is NOT a zone key must not
// authenticate the delegation.
func TestR043_ChainLinkRejectsIneligibleDSMatch(t *testing.T) {
	zone := "example.com."
	nonZone := dnspkg.DNSKEYRecord{KeyTag: 4321, Flags: 0, Protocol: 3, Algorithm: 8, PublicKey: "dGVzdE5vblpvbmU="}
	digest, err := ComputeDSDigestFromDNSKEY(zone, nonZone, 2)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	ds := []dnspkg.DSRecord{{KeyTag: 4321, Algorithm: 8, DigestType: 2, Digest: digest}}
	if link, err := ValidateChainLink(ds, []dnspkg.DNSKEYRecord{nonZone}, zone); err == nil && link != nil && link.DSMatchesKSK {
		t.Fatal("a non-zone key must not satisfy the DS chain link")
	}
}

// R-043: CollectDSMatchedKeys must exclude ineligible keys even when their digest
// matches a DS record.
func TestR043_CollectDSMatchedKeysExcludesIneligible(t *testing.T) {
	zone := "example.com."
	revoked := dnspkg.DNSKEYRecord{KeyTag: 7777, Flags: 257 | 0x0080, Protocol: 3, Algorithm: 8, PublicKey: "cmV2b2tlZEtleQ==", IsRevoked: true}
	digest, err := ComputeDSDigestFromDNSKEY(zone, revoked, 2)
	if err != nil {
		t.Fatalf("compute digest: %v", err)
	}
	ds := []dnspkg.DSRecord{{KeyTag: 7777, Algorithm: 8, DigestType: 2, Digest: digest}}
	if got := CollectDSMatchedKeys(ds, []dnspkg.DNSKEYRecord{revoked}, zone); len(got) != 0 {
		t.Fatalf("revoked key must not be DS-matched, got %d keys", len(got))
	}
}
