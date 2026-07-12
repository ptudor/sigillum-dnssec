package validator

import (
	"strings"
	"testing"
	"time"

	miekgdns "github.com/miekg/dns"
	dns "github.com/ptudor/dnssec-validator/internal/dns"
)

func TestVerifyRRSIGValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		rrsig    dns.RRSIGRecord
		expected bool
	}{
		{
			name: "valid signature",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(-1 * time.Hour),
				Expiration: now.Add(1 * time.Hour),
			},
			expected: true,
		},
		{
			name: "expired signature",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(-2 * time.Hour),
				Expiration: now.Add(-1 * time.Hour),
				IsExpired:  true,
			},
			expected: false,
		},
		{
			name: "not yet valid",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(1 * time.Hour),
				Expiration: now.Add(2 * time.Hour),
			},
			expected: false,
		},
		{
			name: "inception equals now",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(-1 * time.Second),
				Expiration: now.Add(1 * time.Hour),
			},
			expected: true,
		},
		// RFC 4035 Section 5.3.1 clock skew tolerance tests
		{
			name: "clock skew: inception 3 min in future (within tolerance)",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(3 * time.Minute),
				Expiration: now.Add(1 * time.Hour),
			},
			expected: true, // Should pass with 5-min tolerance
		},
		{
			name: "clock skew: expiration 3 min in past (within tolerance)",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(-1 * time.Hour),
				Expiration: now.Add(-3 * time.Minute),
			},
			expected: true, // Should pass with 5-min tolerance
		},
		{
			name: "clock skew: inception 10 min in future (exceeds tolerance)",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(10 * time.Minute),
				Expiration: now.Add(1 * time.Hour),
			},
			expected: false, // Should fail - too far in future
		},
		{
			name: "clock skew: expiration 10 min in past (exceeds tolerance)",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(-1 * time.Hour),
				Expiration: now.Add(-10 * time.Minute),
			},
			expected: false, // Should fail - too far in past
		},
		{
			name: "clock skew: exactly at 5 min tolerance boundary (inception)",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(5*time.Minute - time.Second),
				Expiration: now.Add(1 * time.Hour),
			},
			expected: true, // Just within tolerance
		},
		{
			name: "clock skew: exactly at 5 min tolerance boundary (expiration)",
			rrsig: dns.RRSIGRecord{
				Inception:  now.Add(-1 * time.Hour),
				Expiration: now.Add(-5*time.Minute + time.Second),
			},
			expected: true, // Just within tolerance
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyRRSIGValid(tt.rrsig)
			if result != tt.expected {
				t.Errorf("VerifyRRSIGValid() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestFindRRSIGForType(t *testing.T) {
	rrsigs := []dns.RRSIGRecord{
		{TypeCovered: 1, KeyTag: 12345},  // A
		{TypeCovered: 48, KeyTag: 23456}, // DNSKEY
		{TypeCovered: 43, KeyTag: 34567}, // DS
		{TypeCovered: 28, KeyTag: 45678}, // AAAA
	}

	tests := []struct {
		name        string
		rrtype      uint16
		expectFound bool
		expectTag   uint16
	}{
		{name: "find DNSKEY RRSIG", rrtype: 48, expectFound: true, expectTag: 23456},
		{name: "find DS RRSIG", rrtype: 43, expectFound: true, expectTag: 34567},
		{name: "find A RRSIG", rrtype: 1, expectFound: true, expectTag: 12345},
		{name: "not found", rrtype: 15, expectFound: false}, // MX
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindRRSIGForType(tt.rrtype, rrsigs)
			if tt.expectFound {
				if result == nil {
					t.Errorf("FindRRSIGForType(%d) returned nil, expected non-nil", tt.rrtype)
				} else if result.KeyTag != tt.expectTag {
					t.Errorf("FindRRSIGForType(%d).KeyTag = %d, expected %d", tt.rrtype, result.KeyTag, tt.expectTag)
				}
			} else {
				if result != nil {
					t.Errorf("FindRRSIGForType(%d) returned non-nil, expected nil", tt.rrtype)
				}
			}
		})
	}
}

func TestFindKSKByKeyTag(t *testing.T) {
	dnskeys := []dns.DNSKEYRecord{
		{KeyTag: 12345, Flags: 256, IsKSK: false, IsZSK: true}, // ZSK
		{KeyTag: 23456, Flags: 257, IsKSK: true, IsZSK: false}, // KSK
		{KeyTag: 34567, Flags: 256, IsKSK: false, IsZSK: true}, // ZSK
	}

	tests := []struct {
		name        string
		keyTag      uint16
		expectFound bool
	}{
		{name: "find KSK", keyTag: 23456, expectFound: true},
		{name: "ZSK not returned", keyTag: 12345, expectFound: false},
		{name: "not found", keyTag: 65535, expectFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FindKSKByKeyTag(tt.keyTag, dnskeys)
			if tt.expectFound && result == nil {
				t.Errorf("FindKSKByKeyTag(%d) returned nil, expected non-nil", tt.keyTag)
			} else if !tt.expectFound && result != nil {
				t.Errorf("FindKSKByKeyTag(%d) returned non-nil, expected nil", tt.keyTag)
			}
		})
	}
}

func TestFindDNSKEYByKeyTag(t *testing.T) {
	dnskeys := []dns.DNSKEYRecord{
		{KeyTag: 12345, Flags: 256},
		{KeyTag: 23456, Flags: 257},
	}

	result := FindDNSKEYByKeyTag(12345, dnskeys)
	if result == nil {
		t.Error("FindDNSKEYByKeyTag should find ZSK")
	}

	result = FindDNSKEYByKeyTag(23456, dnskeys)
	if result == nil {
		t.Error("FindDNSKEYByKeyTag should find KSK")
	}

	result = FindDNSKEYByKeyTag(65535, dnskeys)
	if result != nil {
		t.Error("FindDNSKEYByKeyTag should return nil for non-existent tag")
	}
}

func TestGetKSKsAndZSKs(t *testing.T) {
	dnskeys := []dns.DNSKEYRecord{
		{KeyTag: 1, IsKSK: false, IsZSK: true},
		{KeyTag: 2, IsKSK: true, IsZSK: false},
		{KeyTag: 3, IsKSK: false, IsZSK: true},
		{KeyTag: 4, IsKSK: true, IsZSK: false},
	}

	ksks := GetKSKs(dnskeys)
	if len(ksks) != 2 {
		t.Errorf("GetKSKs returned %d keys, expected 2", len(ksks))
	}

	zsks := GetZSKs(dnskeys)
	if len(zsks) != 2 {
		t.Errorf("GetZSKs returned %d keys, expected 2", len(zsks))
	}
}

func TestComputeDSDigestFromDNSKEY(t *testing.T) {
	// Test with a known DNSKEY record
	// This is a simplified test - real verification would need actual key material
	dnskey := dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,         // ECDSAP256SHA256
		PublicKey: "dGVzdA==", // base64 encoded "test"
	}

	// Test SHA-256 digest (type 2)
	digest, err := ComputeDSDigestFromDNSKEY("example.com.", dnskey, 2)
	if err != nil {
		t.Errorf("ComputeDSDigestFromDNSKEY failed: %v", err)
	}
	if digest == "" {
		t.Error("ComputeDSDigestFromDNSKEY returned empty digest")
	}
	// Digest should be uppercase hex
	if digest != strings.ToUpper(digest) {
		t.Error("Digest should be uppercase hex")
	}

	// Test SHA-384 digest (type 4)
	digest384, err := ComputeDSDigestFromDNSKEY("example.com.", dnskey, 4)
	if err != nil {
		t.Errorf("ComputeDSDigestFromDNSKEY with SHA-384 failed: %v", err)
	}
	if len(digest384) != 96 { // SHA-384 = 48 bytes = 96 hex chars
		t.Errorf("SHA-384 digest should be 96 hex chars, got %d", len(digest384))
	}

	// Test SHA-1 digest (type 1) - deprecated but should work
	digest1, err := ComputeDSDigestFromDNSKEY("example.com.", dnskey, 1)
	if err != nil {
		t.Errorf("ComputeDSDigestFromDNSKEY with SHA-1 failed: %v", err)
	}
	if len(digest1) != 40 { // SHA-1 = 20 bytes = 40 hex chars
		t.Errorf("SHA-1 digest should be 40 hex chars, got %d", len(digest1))
	}

	// Test unsupported digest type
	_, err = ComputeDSDigestFromDNSKEY("example.com.", dnskey, 99)
	if err == nil {
		t.Error("ComputeDSDigestFromDNSKEY should fail for unsupported digest type")
	}

	// Test invalid base64 public key
	badKey := dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: "not-valid-base64!!!",
	}
	_, err = ComputeDSDigestFromDNSKEY("example.com.", badKey, 2)
	if err == nil {
		t.Error("ComputeDSDigestFromDNSKEY should fail for invalid base64")
	}
}

func TestVerifyDSMatchesDNSKEY(t *testing.T) {
	// Create a DNSKEY and compute its DS digest
	dnskey := dns.DNSKEYRecord{
		KeyTag:    12345,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: "dGVzdA==",
	}

	// Compute the actual digest
	digest, _ := ComputeDSDigestFromDNSKEY("example.com.", dnskey, 2)

	// Create matching DS record
	matchingDS := dns.DSRecord{
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     digest,
	}

	// Should match
	if !VerifyDSMatchesDNSKEY(matchingDS, dnskey, "example.com.") {
		t.Error("VerifyDSMatchesDNSKEY should return true for matching DS")
	}

	// Wrong key tag
	wrongTagDS := dns.DSRecord{
		KeyTag:     65535,
		Algorithm:  13,
		DigestType: 2,
		Digest:     digest,
	}
	if VerifyDSMatchesDNSKEY(wrongTagDS, dnskey, "example.com.") {
		t.Error("VerifyDSMatchesDNSKEY should return false for wrong key tag")
	}

	// Wrong algorithm
	wrongAlgDS := dns.DSRecord{
		KeyTag:     12345,
		Algorithm:  8, // Different algorithm
		DigestType: 2,
		Digest:     digest,
	}
	if VerifyDSMatchesDNSKEY(wrongAlgDS, dnskey, "example.com.") {
		t.Error("VerifyDSMatchesDNSKEY should return false for wrong algorithm")
	}

	// Unsupported digest type must fail closed
	unsupportedDigestDS := dns.DSRecord{
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 99,
		Digest:     digest,
	}
	if VerifyDSMatchesDNSKEY(unsupportedDigestDS, dnskey, "example.com.") {
		t.Error("VerifyDSMatchesDNSKEY should return false for unsupported digest type")
	}

	// Invalid DNSKEY public key must fail closed
	badKey := dns.DNSKEYRecord{
		KeyTag:    12345,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: "not-valid-base64!!!",
	}
	if VerifyDSMatchesDNSKEY(matchingDS, badKey, "example.com.") {
		t.Error("VerifyDSMatchesDNSKEY should return false when DNSKEY is malformed")
	}
}

func TestReconstructDNSKEY(t *testing.T) {
	record := dns.DNSKEYRecord{
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: "dGVzdA==", // base64 "test"
	}

	dnskey, err := reconstructDNSKEY("example.com.", record)
	if err != nil {
		t.Errorf("reconstructDNSKEY failed: %v", err)
	}

	if dnskey.Flags != 257 {
		t.Errorf("Flags = %d, expected 257", dnskey.Flags)
	}
	if dnskey.Protocol != 3 {
		t.Errorf("Protocol = %d, expected 3", dnskey.Protocol)
	}
	if dnskey.Algorithm != 13 {
		t.Errorf("Algorithm = %d, expected 13", dnskey.Algorithm)
	}
	if dnskey.Hdr.Name != "example.com." {
		t.Errorf("Name = %s, expected example.com.", dnskey.Hdr.Name)
	}
	// Note: base64 validation happens when miekg/dns Verify() is called, not here
}

func TestReconstructRRSIG(t *testing.T) {
	now := time.Now()
	record := dns.RRSIGRecord{
		TypeCovered: 48,
		Algorithm:   13,
		Labels:      2,
		OriginalTTL: 3600,
		Expiration:  now.Add(24 * time.Hour),
		Inception:   now.Add(-1 * time.Hour),
		KeyTag:      12345,
		SignerName:  "example.com.",
		Signature:   "dGVzdA==", // base64 "test"
	}

	rrsig, err := reconstructRRSIG("example.com.", record)
	if err != nil {
		t.Errorf("reconstructRRSIG failed: %v", err)
	}

	if rrsig.TypeCovered != 48 {
		t.Errorf("TypeCovered = %d, expected 48", rrsig.TypeCovered)
	}
	if rrsig.KeyTag != 12345 {
		t.Errorf("KeyTag = %d, expected 12345", rrsig.KeyTag)
	}
	// Note: base64 validation happens when miekg/dns Verify() is called, not here
}

func TestValidateChainLinkMultiAlgorithm(t *testing.T) {
	// Create DNSKEYs for two algorithms
	dnskey13 := dns.DNSKEYRecord{
		KeyTag:    11111,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13, // ECDSAP256SHA256
		PublicKey: "dGVzdDE=",
		IsKSK:     true,
	}
	dnskey8 := dns.DNSKEYRecord{
		KeyTag:    22222,
		Flags:     257,
		Protocol:  3,
		Algorithm: 8, // RSASHA256
		PublicKey: "dGVzdDI=",
		IsKSK:     true,
	}

	// Compute digests
	digest13, _ := ComputeDSDigestFromDNSKEY("example.com.", dnskey13, 2)
	digest8, _ := ComputeDSDigestFromDNSKEY("example.com.", dnskey8, 2)

	tests := []struct {
		name      string
		ds        []dns.DSRecord
		dnskeys   []dns.DNSKEYRecord
		wantError bool
		errorMsg  string
	}{
		{
			name: "single algorithm - valid",
			ds: []dns.DSRecord{
				{KeyTag: 11111, Algorithm: 13, DigestType: 2, Digest: digest13},
			},
			dnskeys:   []dns.DNSKEYRecord{dnskey13},
			wantError: false,
		},
		{
			name: "two algorithms - both valid",
			ds: []dns.DSRecord{
				{KeyTag: 11111, Algorithm: 13, DigestType: 2, Digest: digest13},
				{KeyTag: 22222, Algorithm: 8, DigestType: 2, Digest: digest8},
			},
			dnskeys:   []dns.DNSKEYRecord{dnskey13, dnskey8},
			wantError: false,
		},
		{
			name: "two algorithms - one missing DNSKEY (RFC 6840 violation)",
			ds: []dns.DSRecord{
				{KeyTag: 11111, Algorithm: 13, DigestType: 2, Digest: digest13},
				{KeyTag: 22222, Algorithm: 8, DigestType: 2, Digest: digest8},
			},
			dnskeys:   []dns.DNSKEYRecord{dnskey13}, // Missing alg 8 DNSKEY
			wantError: true,
			errorMsg:  "algorithm 8",
		},
		{
			name: "multiple DS same algorithm - one matches",
			ds: []dns.DSRecord{
				{KeyTag: 55555, Algorithm: 13, DigestType: 2, Digest: "wrongdigest"}, // Wrong
				{KeyTag: 11111, Algorithm: 13, DigestType: 2, Digest: digest13},      // Correct
			},
			dnskeys:   []dns.DNSKEYRecord{dnskey13},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			link, err := ValidateChainLink(tt.ds, tt.dnskeys, "example.com.")

			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errorMsg != "" && !containsString(err.Error(), tt.errorMsg) {
					t.Errorf("error should contain %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if link == nil || !link.DSMatchesKSK {
					t.Error("chain link should be valid")
				}
			}
		})
	}
}

func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}

func TestDetectWildcardSynthesis(t *testing.T) {
	tests := []struct {
		name       string
		ownerName  string
		rrsigLabel uint8
		want       string
	}{
		{
			name:       "no wildcard - labels match",
			ownerName:  "example.com.",
			rrsigLabel: 2, // example.com has 2 labels
			want:       "",
		},
		{
			name:       "wildcard - one extra label",
			ownerName:  "www.example.com.",
			rrsigLabel: 2, // Signed as *.example.com
			want:       "*.example.com.",
		},
		{
			name:       "wildcard - two extra labels",
			ownerName:  "a.b.example.com.",
			rrsigLabel: 2, // Signed as *.example.com
			want:       "*.example.com.",
		},
		{
			name:       "root zone - no wildcard",
			ownerName:  ".",
			rrsigLabel: 0,
			want:       "",
		},
		{
			name:       "TLD - no wildcard",
			ownerName:  "com.",
			rrsigLabel: 1,
			want:       "",
		},
		{
			name:       "wildcard at TLD level",
			ownerName:  "example.com.",
			rrsigLabel: 1, // Signed as *.com
			want:       "*.com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rrsig := dns.RRSIGRecord{
				Labels: tt.rrsigLabel,
			}
			got := DetectWildcardSynthesis(tt.ownerName, rrsig)
			if got != tt.want {
				t.Errorf("DetectWildcardSynthesis(%q, labels=%d) = %q, want %q",
					tt.ownerName, tt.rrsigLabel, got, tt.want)
			}
		})
	}
}

func TestVerifyRRsetRRSIGFromResponse_EmptyRaw(t *testing.T) {
	key := dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: "dGVzdA==",
	}

	_, err := VerifyRRsetRRSIGFromResponse(nil, miekgdns.TypeA, key, 12345, "", true)
	if err == nil {
		t.Fatal("VerifyRRsetRRSIGFromResponse expected error for empty raw response")
	}
}

func TestVerifyRRsetRRSIGFromResponse_MalformedRaw(t *testing.T) {
	key := dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: "dGVzdA==",
	}

	_, err := VerifyRRsetRRSIGFromResponse([]byte{0x00, 0x01, 0x02}, miekgdns.TypeA, key, 12345, "", true)
	if err == nil {
		t.Fatal("VerifyRRsetRRSIGFromResponse expected error for malformed raw response")
	}
}

func TestVerifyRRsetRRSIGFromResponse_NoMatchingRRSIG(t *testing.T) {
	msg := new(miekgdns.Msg)
	msg.SetQuestion("example.com.", miekgdns.TypeA)
	msg.Answer = append(msg.Answer, &miekgdns.A{
		Hdr: miekgdns.RR_Header{
			Name:   "example.com.",
			Rrtype: miekgdns.TypeA,
			Class:  miekgdns.ClassINET,
			Ttl:    300,
		},
		A: []byte{192, 0, 2, 1},
	})
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("failed to pack test DNS message: %v", err)
	}

	key := dns.DNSKEYRecord{
		Flags:     256,
		Protocol:  3,
		Algorithm: 13,
		PublicKey: "dGVzdA==",
	}

	_, err = VerifyRRsetRRSIGFromResponse(raw, miekgdns.TypeA, key, 12345, "example.com.", true)
	if err == nil {
		t.Fatal("VerifyRRsetRRSIGFromResponse expected error when no matching RRSIG exists")
	}
}
