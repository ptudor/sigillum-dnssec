package validator

import (
	"testing"

	miekgdns "github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

func TestLastNLabels(t *testing.T) {
	tests := []struct {
		qname string
		n     int
		want  string
	}{
		{"foo.example.com.", 2, "example.com."},
		{"a.b.example.com.", 3, "b.example.com."},
		{"foo.example.com.", 3, "foo.example.com."},
		{"foo.example.com.", 5, "foo.example.com."}, // n exceeds label count
		{"foo.example.com.", 0, "."},
		{"example.com", 2, "example.com."}, // normalizes missing trailing dot
	}
	for _, tt := range tests {
		if got := lastNLabels(tt.qname, tt.n); got != tt.want {
			t.Errorf("lastNLabels(%q, %d) = %q, want %q", tt.qname, tt.n, got, tt.want)
		}
	}
}

func TestVerifyWildcardDenial_NSEC(t *testing.T) {
	// Closest encloser for foo.example.com synthesized by *.example.com is example.com
	// (2 labels). A covering NSEC must prove foo.example.com has no exact match.
	covering := []dnspkg.NSECRecord{
		{Owner: "example.com.", NextDomain: "zzz.example.com.", TypeBitmap: []string{"A", "RRSIG", "NSEC"}},
	}
	if proof := VerifyWildcardDenial("foo.example.com.", 2, covering, nil); !proof.Verified {
		t.Fatalf("expected covering NSEC to verify the wildcard denial, error: %q", proof.Error)
	}

	notCovering := []dnspkg.NSECRecord{
		{Owner: "aaa.example.com.", NextDomain: "bbb.example.com.", TypeBitmap: []string{"A"}},
	}
	if proof := VerifyWildcardDenial("foo.example.com.", 2, notCovering, nil); proof.Verified {
		t.Fatal("non-covering NSEC must not verify the wildcard denial")
	}
}

func TestVerifyWildcardDenial_NSEC3(t *testing.T) {
	// The next closer name for foo.example.com (closest encloser example.com, 2 labels)
	// is foo.example.com itself. A covering NSEC3 for its hash proves no closer match.
	hashedNC := computeNSEC3Hash("foo.example.com.", nil, 0)

	covering := []dnspkg.NSEC3Record{{
		HashedOwner: hashedNC[:len(hashedNC)-1], // strictly < hashedNC
		NextHashed:  hashedNC + "0",             // strictly > hashedNC
		Algorithm:   1,
		Salt:        "-",
		Iterations:  0,
		TypeBitmap:  []string{"A", "RRSIG"},
	}}
	if proof := VerifyWildcardDenial("foo.example.com.", 2, nil, covering); !proof.Verified {
		t.Fatalf("expected covering NSEC3 to verify the wildcard denial, error: %q", proof.Error)
	}

	// Both bounds above the hash: the next closer name is not covered.
	notCovering := []dnspkg.NSEC3Record{{
		HashedOwner: hashedNC + "0",
		NextHashed:  hashedNC + "00",
		Algorithm:   1,
		Salt:        "-",
		Iterations:  0,
		TypeBitmap:  []string{"A", "RRSIG"},
	}}
	if proof := VerifyWildcardDenial("foo.example.com.", 2, nil, notCovering); proof.Verified {
		t.Fatal("non-covering NSEC3 must not verify the wildcard denial")
	}
}

func TestVerifyWildcardDenial_NoRecords(t *testing.T) {
	proof := VerifyWildcardDenial("foo.example.com.", 2, nil, nil)
	if proof.Verified {
		t.Fatal("wildcard denial must not verify without NSEC/NSEC3 records")
	}
	if proof.Error == "" {
		t.Fatal("expected an error explaining the missing proof")
	}
}

func TestVerifyWildcard_EndToEnd_Verified(t *testing.T) {
	// A genuine signed NSEC covering foo.example.com accompanies the wildcard answer.
	raw, key, nsec, _ := buildSignedNSECResponse(t, "example.com.", "zzz.example.com.", "zzz.example.com.")
	qr := &dnspkg.QueryResult{RawResponse: raw, NSEC: []dnspkg.NSECRecord{nsec}}
	validation := &RecordValidation{RecordType: "A"}
	aRRSIG := dnspkg.RRSIGRecord{TypeCovered: miekgdns.TypeA, Labels: 2, SignerName: "example.com.", KeyTag: key.KeyTag}

	var v Validator
	v.verifyWildcard(validation, "foo.example.com.", "example.com.", aRRSIG, qr, []dnspkg.DNSKEYRecord{key})

	if !validation.Wildcard {
		t.Fatal("expected wildcard synthesis to be detected")
	}
	if validation.WildcardSource != "*.example.com." {
		t.Fatalf("wildcard source = %q, want %q", validation.WildcardSource, "*.example.com.")
	}
	if !validation.WildcardProofVerified {
		t.Fatalf("expected the closest-encloser proof to verify, error: %q", validation.Error)
	}
	if validation.Error != "" {
		t.Fatalf("unexpected error: %q", validation.Error)
	}
}

func TestVerifyWildcard_EndToEnd_ForgedProofRejected(t *testing.T) {
	// The covering NSEC still covers foo.example.com for the range proof, but its
	// signature is over a different record (served next != signed next), so the
	// cryptographic check must fail and the proof must not be reported as verified.
	raw, key, nsec, _ := buildSignedNSECResponse(t, "example.com.", "zzz.example.com.", "yyy.example.com.")
	qr := &dnspkg.QueryResult{RawResponse: raw, NSEC: []dnspkg.NSECRecord{nsec}}
	validation := &RecordValidation{RecordType: "A"}
	aRRSIG := dnspkg.RRSIGRecord{TypeCovered: miekgdns.TypeA, Labels: 2, SignerName: "example.com.", KeyTag: key.KeyTag}

	var v Validator
	v.verifyWildcard(validation, "foo.example.com.", "example.com.", aRRSIG, qr, []dnspkg.DNSKEYRecord{key})

	if !validation.Wildcard {
		t.Fatal("expected wildcard synthesis to be detected")
	}
	if validation.WildcardProofVerified {
		t.Fatal("a forged closest-encloser proof must not be reported as verified")
	}
	if validation.Error == "" {
		t.Fatal("expected an error explaining the unverified wildcard proof")
	}
}

func TestVerifyWildcard_NotWildcard(t *testing.T) {
	// owner labels == RRSIG labels: not wildcard-synthesized, nothing recorded.
	validation := &RecordValidation{RecordType: "A"}
	qr := &dnspkg.QueryResult{}
	aRRSIG := dnspkg.RRSIGRecord{TypeCovered: miekgdns.TypeA, Labels: 3, SignerName: "example.com."}

	var v Validator
	v.verifyWildcard(validation, "foo.example.com.", "example.com.", aRRSIG, qr, nil)

	if validation.Wildcard {
		t.Fatal("a non-wildcard answer must not be flagged as wildcard")
	}
	if validation.WildcardProof != nil {
		t.Fatal("no wildcard proof should be recorded for a non-wildcard answer")
	}
}
