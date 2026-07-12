package validator

import (
	"testing"

	miekgdns "github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// R-030: a parent-side delegation NSEC/NSEC3 (NS set, SOA clear) must not be
// accepted as an authoritative NODATA proof — otherwise an unauthenticated
// zone-cut turns a signed parent referral into a false secure NODATA.
func TestR030_DelegationNSECNotNODATA(t *testing.T) {
	qname := canonicalizeName("sub.example.")

	// Delegation pattern: NS present, SOA absent, queried A absent.
	deleg := []dnspkg.NSECRecord{{Owner: qname, NextDomain: "z.example.", TypeBitmap: []string{"NS", "RRSIG"}}}
	if _, err := verifyNSECNODATA(qname, miekgdns.TypeA, deleg); err == nil {
		t.Fatal("NS-without-SOA NSEC must not prove NODATA (parent referral)")
	}

	// Apex NODATA: SOA + NS present, A absent → valid authoritative NODATA.
	apex := []dnspkg.NSECRecord{{Owner: qname, NextDomain: "z.example.", TypeBitmap: []string{"SOA", "NS", "RRSIG"}}}
	if proof, err := verifyNSECNODATA(qname, miekgdns.TypeA, apex); err != nil || proof == nil {
		t.Fatalf("apex NSEC (SOA+NS, no A) must prove NODATA: %v", err)
	}

	// Ordinary owner NODATA: no NS, A absent → valid.
	ordinary := []dnspkg.NSECRecord{{Owner: qname, NextDomain: "z.example.", TypeBitmap: []string{"TXT", "RRSIG"}}}
	if proof, err := verifyNSECNODATA(qname, miekgdns.TypeA, ordinary); err != nil || proof == nil {
		t.Fatalf("ordinary-owner NSEC (no NS) must prove NODATA: %v", err)
	}
}

// R-030 (NSEC3): the same delegation pattern must be rejected in the NSEC3 NODATA path.
func TestR030_DelegationNSEC3NotNODATA(t *testing.T) {
	qname := canonicalizeName("sub.example.")
	salt, _ := hexDecode("AABB")
	h := computeNSEC3Hash(qname, salt, 0)

	deleg := []dnspkg.NSEC3Record{{Algorithm: 1, Iterations: 0, Salt: "AABB", HashedOwner: h, NextHashed: h, TypeBitmap: []string{"NS", "RRSIG"}}}
	if _, err := verifyNSEC3NODATA(h, qname, miekgdns.TypeA, deleg); err == nil {
		t.Fatal("NS-without-SOA NSEC3 must not prove NODATA (parent referral)")
	}
}
