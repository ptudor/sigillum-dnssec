package validator

import (
	"testing"

	miekgdns "github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// R-037: records that differ in (algorithm, iterations, salt) belong to distinct
// NSEC3 chains and must be partitioned so no proof cross-combines them.
func TestR037_GroupNSEC3ByParams(t *testing.T) {
	recs := []dnspkg.NSEC3Record{
		{Algorithm: 1, Iterations: 0, Salt: "AABB"},
		{Algorithm: 1, Iterations: 0, Salt: "CCDD"}, // different salt → different chain
		{Algorithm: 1, Iterations: 5, Salt: "AABB"}, // different iterations → different chain
		{Algorithm: 1, Iterations: 0, Salt: "aabb"}, // same as first (salt case-insensitive)
	}
	groups := groupNSEC3ByParams(recs)
	if len(groups) != 3 {
		t.Fatalf("expected 3 parameter groups, got %d", len(groups))
	}
	// The salt-AABB/iter-0 group must contain the two AABB records (case-insensitive).
	if len(groups[0]) != 2 {
		t.Fatalf("first group should hold both AABB/iter0 records, got %d", len(groups[0]))
	}
}

// R-037: a NODATA proof must still verify when the proving chain is not the first
// record in the response (a parameter-transition response), proving each chain is
// tried independently rather than only records[0]'s parameters being used.
func TestR037_ProvesViaConsistentChainRegardlessOfOrder(t *testing.T) {
	const qname = "host.example."
	saltReal, err := hexDecode("AABB")
	if err != nil {
		t.Fatal(err)
	}
	hReal := computeNSEC3Hash(canonicalizeName(qname), saltReal, 0)

	// Real chain (salt AABB): exact match at the queried name, without the queried
	// type — a valid NODATA proof for type A.
	real := dnspkg.NSEC3Record{Algorithm: 1, Iterations: 0, Salt: "AABB", HashedOwner: hReal, NextHashed: hReal, TypeBitmap: []string{"RRSIG"}}
	// Decoy chain (different salt CCDD) placed first; its hash space is unrelated.
	decoy := dnspkg.NSEC3Record{Algorithm: 1, Iterations: 0, Salt: "CCDD", HashedOwner: "ZZZZZZZZ", NextHashed: "ZZZZZZZZ", TypeBitmap: []string{"A"}}

	proof, err := VerifyNSEC3Denial(qname, miekgdns.TypeA, []dnspkg.NSEC3Record{decoy, real}, "example.", 0)
	if err != nil || proof == nil {
		t.Fatalf("NODATA must verify via the consistent (AABB) chain regardless of order: %v", err)
	}
}
