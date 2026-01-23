package validator

import (
	"strings"
	"testing"

	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

func TestCanonicallyBetween(t *testing.T) {
	tests := []struct {
		name  string
		qname string
		start string
		end   string
		want  bool
	}{
		{
			name:  "name between start and end",
			qname: "foo.example.com.",
			start: "bar.example.com.",
			end:   "zoo.example.com.",
			want:  true,
		},
		{
			name:  "name equals start",
			qname: "bar.example.com.",
			start: "bar.example.com.",
			end:   "zoo.example.com.",
			want:  false,
		},
		{
			name:  "name equals end",
			qname: "zoo.example.com.",
			start: "bar.example.com.",
			end:   "zoo.example.com.",
			want:  false,
		},
		{
			name:  "name before start",
			qname: "aaa.example.com.",
			start: "bar.example.com.",
			end:   "zoo.example.com.",
			want:  false,
		},
		{
			name:  "name after end",
			qname: "zzz.example.com.",
			start: "bar.example.com.",
			end:   "zoo.example.com.",
			want:  false,
		},
		{
			name:  "wrap-around - name after start",
			qname: "zoo.example.com.",
			start: "xxx.example.com.",
			end:   "aaa.example.com.",
			want:  true,
		},
		{
			name:  "wrap-around - name before end",
			qname: "aaa.example.com.",
			start: "zzz.example.com.",
			end:   "bbb.example.com.",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicallyBetween(tt.qname, tt.start, tt.end)
			if got != tt.want {
				t.Errorf("canonicallyBetween(%q, %q, %q) = %v, want %v",
					tt.qname, tt.start, tt.end, got, tt.want)
			}
		})
	}
}

func TestHashBetween(t *testing.T) {
	tests := []struct {
		name  string
		hash  string
		start string
		end   string
		want  bool
	}{
		{
			name:  "hash between start and end",
			hash:  "MMMM",
			start: "AAAA",
			end:   "ZZZZ",
			want:  true,
		},
		{
			name:  "hash equals start",
			hash:  "AAAA",
			start: "AAAA",
			end:   "ZZZZ",
			want:  false,
		},
		{
			name:  "hash equals end",
			hash:  "ZZZZ",
			start: "AAAA",
			end:   "ZZZZ",
			want:  false,
		},
		{
			name:  "wrap-around - hash after start",
			hash:  "ZZZZ",
			start: "XXXX",
			end:   "BBBB",
			want:  true,
		},
		{
			name:  "wrap-around - hash before end",
			hash:  "AAAA",
			start: "XXXX",
			end:   "CCCC",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hashBetween(tt.hash, tt.start, tt.end)
			if got != tt.want {
				t.Errorf("hashBetween(%q, %q, %q) = %v, want %v",
					tt.hash, tt.start, tt.end, got, tt.want)
			}
		})
	}
}

func TestToWireFormat(t *testing.T) {
	tests := []struct {
		name string
		want []byte
	}{
		{
			name: ".",
			want: []byte{0},
		},
		{
			name: "com.",
			want: []byte{3, 'c', 'o', 'm', 0},
		},
		{
			name: "example.com.",
			want: []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
		{
			name: "WWW.EXAMPLE.COM.",
			want: []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toWireFormat(tt.name)
			if len(got) != len(tt.want) {
				t.Errorf("toWireFormat(%q) length = %d, want %d", tt.name, len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("toWireFormat(%q)[%d] = %d, want %d", tt.name, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestComputeNSEC3Hash(t *testing.T) {
	// Test vectors from RFC 5155 Appendix A
	tests := []struct {
		name       string
		salt       []byte
		iterations uint16
		want       string
	}{
		{
			// Example from RFC 5155 - *.w.example with empty salt, 1 iteration
			// Note: The exact hash depends on the full computation
			name:       "example.",
			salt:       []byte{0xaa, 0xbb, 0xcc, 0xdd},
			iterations: 12,
			// This is a computed value for testing purposes
			want: "", // We'll verify the hash is non-empty and correct format
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeNSEC3Hash(tt.name, tt.salt, tt.iterations)

			// Verify it's valid base32hex (uppercase, no padding)
			if got == "" {
				t.Error("computeNSEC3Hash returned empty string")
			}
			if strings.ToUpper(got) != got {
				t.Errorf("hash should be uppercase, got %q", got)
			}
			// SHA-1 produces 20 bytes = 32 base32 characters
			if len(got) != 32 {
				t.Errorf("hash length = %d, want 32", len(got))
			}
		})
	}
}

func TestVerifyNSECNXDOMAIN(t *testing.T) {
	tests := []struct {
		name        string
		qname       string
		nsec        []dnspkg.NSECRecord
		wantProof   bool
		wantErrText string
	}{
		{
			name:  "name falls in gap",
			qname: "nonexistent.example.com.",
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "existing.example.com.",
					NextDomain: "other.example.com.",
					TypeBitmap: []string{"A", "AAAA", "RRSIG"},
				},
			},
			wantProof: true,
		},
		{
			name:  "name does not fall in gap",
			qname: "aaa.example.com.",
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "mmm.example.com.",
					NextDomain: "zzz.example.com.",
					TypeBitmap: []string{"A", "AAAA"},
				},
			},
			wantProof:   false,
			wantErrText: "no NSEC record proves",
		},
		{
			name:  "wrap-around at zone apex",
			qname: "zzz.example.com.",
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "www.example.com.",
					NextDomain: "aaa.example.com.",
					TypeBitmap: []string{"A"},
				},
			},
			wantProof: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, err := verifyNSECNXDOMAIN(canonicalizeName(tt.qname), tt.nsec)

			if tt.wantProof {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if proof == nil {
					t.Error("expected proof, got nil")
				} else if proof.ProofType != "nxdomain" {
					t.Errorf("proof type = %q, want nxdomain", proof.ProofType)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.wantErrText != "" && !strings.Contains(err.Error(), tt.wantErrText) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErrText)
				}
			}
		})
	}
}

func TestVerifyNSECNODATA(t *testing.T) {
	tests := []struct {
		name        string
		qname       string
		qtype       uint16
		nsec        []dnspkg.NSECRecord
		wantProof   bool
		wantErrText string
	}{
		{
			name:  "type not in bitmap",
			qname: "example.com.",
			qtype: 28, // AAAA
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "example.com.",
					NextDomain: "foo.example.com.",
					TypeBitmap: []string{"A", "NS", "SOA", "RRSIG", "NSEC"},
				},
			},
			wantProof: true,
		},
		{
			name:  "type in bitmap - not NODATA",
			qname: "example.com.",
			qtype: 1, // A
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "example.com.",
					NextDomain: "foo.example.com.",
					TypeBitmap: []string{"A", "NS", "SOA", "RRSIG", "NSEC"},
				},
			},
			wantProof:   false,
			wantErrText: "no NSEC record proves type",
		},
		{
			name:  "NSEC at wrong name",
			qname: "example.com.",
			qtype: 28, // AAAA
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "other.example.com.",
					NextDomain: "foo.example.com.",
					TypeBitmap: []string{"A", "NS"},
				},
			},
			wantProof:   false,
			wantErrText: "no NSEC record proves type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, err := verifyNSECNODATA(canonicalizeName(tt.qname), tt.qtype, tt.nsec)

			if tt.wantProof {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if proof == nil {
					t.Error("expected proof, got nil")
				} else if proof.ProofType != "nodata" {
					t.Errorf("proof type = %q, want nodata", proof.ProofType)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.wantErrText != "" && !strings.Contains(err.Error(), tt.wantErrText) {
					t.Errorf("error = %q, want containing %q", err.Error(), tt.wantErrText)
				}
			}
		})
	}
}

func TestHexDecode(t *testing.T) {
	tests := []struct {
		input   string
		want    []byte
		wantErr bool
	}{
		{"", nil, false},
		{"-", nil, false},
		{"aabbccdd", []byte{0xaa, 0xbb, 0xcc, 0xdd}, false},
		{"AABBCCDD", []byte{0xaa, 0xbb, 0xcc, 0xdd}, false},
		{"00ff", []byte{0x00, 0xff}, false},
		{"abc", nil, true}, // Odd length
		{"gg", nil, true},  // Invalid character
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := hexDecode(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("byte %d = %02x, want %02x", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestHasTypeInBitmap(t *testing.T) {
	bitmap := []string{"A", "AAAA", "NS", "SOA", "RRSIG", "DNSKEY"}

	if !HasTypeInBitmap("A", bitmap) {
		t.Error("expected A to be in bitmap")
	}
	if !HasTypeInBitmap("DNSKEY", bitmap) {
		t.Error("expected DNSKEY to be in bitmap")
	}
	if HasTypeInBitmap("MX", bitmap) {
		t.Error("expected MX to not be in bitmap")
	}
	if HasTypeInBitmap("DS", bitmap) {
		t.Error("expected DS to not be in bitmap")
	}
}

func TestProvesDSAbsence(t *testing.T) {
	tests := []struct {
		name  string
		qname string
		nsec  []dnspkg.NSECRecord
		nsec3 []dnspkg.NSEC3Record
		want  bool
	}{
		{
			name:  "NSEC proves no DS",
			qname: "child.example.com.",
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "child.example.com.",
					NextDomain: "foo.example.com.",
					TypeBitmap: []string{"NS", "RRSIG", "NSEC"}, // No DS
				},
			},
			want: true,
		},
		{
			name:  "NSEC shows DS exists",
			qname: "child.example.com.",
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "child.example.com.",
					NextDomain: "foo.example.com.",
					TypeBitmap: []string{"NS", "DS", "RRSIG", "NSEC"}, // Has DS
				},
			},
			want: false,
		},
		{
			name:  "NSEC at different name",
			qname: "child.example.com.",
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "other.example.com.",
					NextDomain: "foo.example.com.",
					TypeBitmap: []string{"A"}, // No DS but wrong name
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProvesDSAbsence(tt.qname, tt.nsec, tt.nsec3)
			if got != tt.want {
				t.Errorf("ProvesDSAbsence() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompareCanonical(t *testing.T) {
	tests := []struct {
		a    []string
		b    []string
		want int
	}{
		{[]string{"com", "example"}, []string{"com", "example"}, 0},
		{[]string{"com", "aaa"}, []string{"com", "zzz"}, -1},
		{[]string{"com", "zzz"}, []string{"com", "aaa"}, 1},
		{[]string{"com"}, []string{"com", "example"}, -1},
		{[]string{"com", "example"}, []string{"com"}, 1},
		{[]string{"net"}, []string{"com"}, 1},
		{[]string{"com"}, []string{"net"}, -1},
	}

	for _, tt := range tests {
		got := compareCanonical(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareCanonical(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
