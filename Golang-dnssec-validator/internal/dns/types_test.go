package dns

import (
	"testing"
)

func TestAlgorithmName(t *testing.T) {
	tests := []struct {
		alg      uint8
		expected string
	}{
		{5, "RSASHA1"},
		{7, "RSASHA1-NSEC3-SHA1"},
		{8, "RSASHA256"},
		{10, "RSASHA512"},
		{13, "ECDSAP256SHA256"},
		{14, "ECDSAP384SHA384"},
		{15, "ED25519"},
		{16, "ED448"},
		{0, "UNKNOWN"},
		{99, "UNKNOWN"},
	}

	for _, tt := range tests {
		result := AlgorithmName(tt.alg)
		if result != tt.expected {
			t.Errorf("AlgorithmName(%d) = %q, want %q", tt.alg, result, tt.expected)
		}
	}
}

func TestDigestTypeName(t *testing.T) {
	tests := []struct {
		dt       uint8
		expected string
	}{
		{1, "SHA-1"},
		{2, "SHA-256"},
		{4, "SHA-384"},
		{0, "UNKNOWN"},
		{3, "UNKNOWN"},
		{99, "UNKNOWN"},
	}

	for _, tt := range tests {
		result := DigestTypeName(tt.dt)
		if result != tt.expected {
			t.Errorf("DigestTypeName(%d) = %q, want %q", tt.dt, result, tt.expected)
		}
	}
}

func TestRCodeName(t *testing.T) {
	tests := []struct {
		rcode    int
		expected string
	}{
		{0, "NOERROR"},
		{1, "FORMERR"},
		{2, "SERVFAIL"},
		{3, "NXDOMAIN"},
		{4, "NOTIMP"},
		{5, "REFUSED"},
		{6, "UNKNOWN"},
		{-1, "UNKNOWN"},
	}

	for _, tt := range tests {
		result := RCodeName(tt.rcode)
		if result != tt.expected {
			t.Errorf("RCodeName(%d) = %q, want %q", tt.rcode, result, tt.expected)
		}
	}
}

func TestTypeName(t *testing.T) {
	tests := []struct {
		t        uint16
		expected string
	}{
		{1, "A"},
		{2, "NS"},
		{5, "CNAME"},
		{6, "SOA"},
		{15, "MX"},
		{16, "TXT"},
		{28, "AAAA"},
		{43, "DS"},
		{46, "RRSIG"},
		{47, "NSEC"},
		{48, "DNSKEY"},
		{50, "NSEC3"},
		{51, "NSEC3PARAM"},
		{257, "CAA"},
		{0, "UNKNOWN"},
		{999, "UNKNOWN"},
	}

	for _, tt := range tests {
		result := TypeName(tt.t)
		if result != tt.expected {
			t.Errorf("TypeName(%d) = %q, want %q", tt.t, result, tt.expected)
		}
	}
}
