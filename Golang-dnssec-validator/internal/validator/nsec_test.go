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
	// Fixed vectors: RFC 5155 Appendix A (salt aabbccdd, 12 iterations) plus
	// independently computed values (Python hashlib over the canonical wire
	// name, RFC 5155 §5) for an empty salt, zero and several iterations, owner
	// case and a label with a binary octet. A wrong hash, salt or iteration
	// handling fails here (RA6X-050).
	saltA := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	tests := []struct {
		name       string
		salt       []byte
		iterations uint16
		want       string
	}{
		{"example.", saltA, 12, "0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM"},
		{"a.example.", saltA, 12, "35MTHGPGCU1QG68FAB165KLNSNK3DPVL"},
		{"ai.example.", saltA, 12, "GJEQE526PLBF1G8MKLP59ENFD789NJGI"},
		{"ns1.example.", saltA, 12, "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR"},
		{"*.w.example.", saltA, 12, "R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN"},
		{"x.y.w.example.", saltA, 12, "2VPTU5TIMAMQTTGL4LUU9KG21E0AOR3S"},
		{"xx.example.", saltA, 12, "T644EBQK9BIBCNA874GIVR6JOJ62MLHV"},
		{"example.", nil, 0, "3MSEV9USMD4BR9S97V51R2TDVMR9IQO1"},
		{"EXAMPLE.", nil, 0, "3MSEV9USMD4BR9S97V51R2TDVMR9IQO1"}, // owner case is canonicalized
		{"example", nil, 0, "3MSEV9USMD4BR9S97V51R2TDVMR9IQO1"},  // missing trailing dot
		{"example.", nil, 5, "POMLVMMH82T6P8PG24NPK8RDR7KUPOOI"},
		{`x\000y.example.`, nil, 0, "EN9UU3BEVDHKQ7FV3QPAFLPA9N3I25K1"}, // binary octet in a label
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeNSEC3Hash(tt.name, tt.salt, tt.iterations)
			if got != tt.want {
				t.Fatalf("computeNSEC3Hash(%q, %x, %d) = %q, want %q", tt.name, tt.salt, tt.iterations, got, tt.want)
			}
			if strings.ToUpper(got) != got || len(got) != 32 {
				t.Errorf("hash must be 32 uppercase base32hex characters, got %q", got)
			}
		})
	}
}

func TestVerifyNSECNXDOMAIN(t *testing.T) {
	// A complete NXDOMAIN proof (RFC 4035 §5.4) needs the NSEC covering qname AND an NSEC
	// covering the wildcard "*.<closest-encloser>". For qname nonexistent.example.com. the
	// closest encloser is example.com., so the wildcard is *.example.com. The apex NSEC
	// (example.com. -> existing.example.com.) covers that wildcard in canonical order.
	tests := []struct {
		name        string
		qname       string
		nsec        []dnspkg.NSECRecord
		wantProof   bool
		wantErrText string
	}{
		{
			name:  "complete proof: covering NSEC + wildcard NSEC",
			qname: "nonexistent.example.com.",
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "existing.example.com.",
					NextDomain: "other.example.com.",
					TypeBitmap: []string{"A", "AAAA", "RRSIG"},
				},
				{
					Owner:      "example.com.",
					NextDomain: "existing.example.com.",
					TypeBitmap: []string{"A", "NS", "SOA", "RRSIG"},
				},
			},
			wantProof: true,
		},
		{
			name:  "incomplete: covering NSEC only, no wildcard-nonexistence proof",
			qname: "nonexistent.example.com.",
			nsec: []dnspkg.NSECRecord{
				{
					Owner:      "existing.example.com.",
					NextDomain: "other.example.com.",
					TypeBitmap: []string{"A", "AAAA", "RRSIG"},
				},
			},
			wantProof:   false,
			wantErrText: "wildcard",
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
			wantErrText: "NODATA is not proven",
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

func TestClosestEncloserFromNSEC(t *testing.T) {
	tests := []struct {
		qname, owner, next, want string
	}{
		// Closest encloser is example.com. (bar.example.com. is not proven to exist).
		{"nonexistent.example.com.", "existing.example.com.", "other.example.com.", "example.com."},
		// bar.example.com. is the owner (exists) and is an ancestor of qname -> it is the CE.
		{"foo.bar.example.com.", "bar.example.com.", "zoo.example.com.", "bar.example.com."},
		// The covering NSEC skips over bar.example.com., so the CE is example.com.
		{"foo.bar.example.com.", "aaa.example.com.", "zzz.example.com.", "example.com."},
	}
	for _, tt := range tests {
		got := closestEncloserFromNSEC(canonicalizeName(tt.qname), canonicalizeName(tt.owner), canonicalizeName(tt.next))
		if got != tt.want {
			t.Errorf("closestEncloserFromNSEC(%s, %s, %s) = %s, want %s", tt.qname, tt.owner, tt.next, got, tt.want)
		}
	}
}

// R-085: an NSEC3 NXDOMAIN proof requires the closest-encloser match, the next-closer
// cover, and the wildcard cover — a single covering NSEC3 is not sufficient.
func TestVerifyNSEC3NXDOMAINComplete(t *testing.T) {
	const salt = "AABBCCDD"
	const iter = uint16(5)
	saltBytes, err := hexDecode(salt)
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	hCE := computeNSEC3Hash("example.com.", saltBytes, iter)

	minH := strings.Repeat("0", 32)
	maxH := strings.Repeat("V", 32)

	ceMatch := dnspkg.NSEC3Record{HashedOwner: hCE, NextHashed: maxH, Algorithm: 1, Salt: salt, Iterations: iter, TypeBitmap: []string{"NS", "SOA", "RRSIG"}}
	wideCover := dnspkg.NSEC3Record{HashedOwner: minH, NextHashed: maxH, Algorithm: 1, Salt: salt, Iterations: iter, TypeBitmap: []string{"A", "RRSIG"}}

	// Complete trio: CE match + covers for the next closer and the wildcard.
	proof, err := verifyNSEC3NXDOMAIN("", "nonexistent.example.com.", []dnspkg.NSEC3Record{ceMatch, wideCover})
	if err != nil {
		t.Fatalf("complete NSEC3 NXDOMAIN proof should verify, got: %v", err)
	}
	if proof == nil || proof.ProofType != "nxdomain" {
		t.Fatalf("expected an nxdomain proof, got %+v", proof)
	}

	// Incomplete: a single covering NSEC3 with no closest-encloser match.
	if _, err := verifyNSEC3NXDOMAIN("", "nonexistent.example.com.", []dnspkg.NSEC3Record{wideCover}); err == nil {
		t.Fatal("a single covering NSEC3 must not be accepted as a complete NXDOMAIN proof")
	}
}

func TestVerifyNODATA_CNAMEBit(t *testing.T) {
	// NSEC with the CNAME bit set must not prove NODATA (RFC 6840 §4.3).
	nsec := []dnspkg.NSECRecord{{
		Owner:      "alias.example.com.",
		NextDomain: "foo.example.com.",
		TypeBitmap: []string{"CNAME", "RRSIG", "NSEC"},
	}}
	if _, err := verifyNSECNODATA(canonicalizeName("alias.example.com."), 28 /* AAAA */, nsec); err == nil {
		t.Fatal("NSEC NODATA proof with the CNAME bit set must be rejected")
	}

	// NSEC3 with the CNAME bit set must likewise be rejected.
	const salt = "AABBCCDD"
	const iter = uint16(5)
	saltBytes, _ := hexDecode(salt)
	h := computeNSEC3Hash("alias.example.com.", saltBytes, iter)
	nsec3 := []dnspkg.NSEC3Record{{HashedOwner: h, NextHashed: strings.Repeat("V", 32), Algorithm: 1, Salt: salt, Iterations: iter, TypeBitmap: []string{"CNAME", "RRSIG"}}}
	if _, err := verifyNSEC3NODATA(h, "alias.example.com.", 28, nsec3); err == nil {
		t.Fatal("NSEC3 NODATA proof with the CNAME bit set must be rejected")
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

// R-088: NSEC3 records with iteration counts above the RFC 9276 cap are refused
// before any hashing, so a hostile zone can't force up to 65536 SHA-1 ops/name.
func TestNSEC3IterationCap(t *testing.T) {
	over := []dnspkg.NSEC3Record{{
		HashedOwner: strings.Repeat("A", 32), NextHashed: strings.Repeat("Z", 32),
		Algorithm: NSEC3HashSHA1, Salt: "", Iterations: 1000,
		TypeBitmap: []string{"A", "RRSIG"},
	}}

	// Direct denial verification rejects with a cap error.
	if _, err := VerifyNSEC3Denial("nx.example.com.", 1, over, "example.com.", 3); err == nil {
		t.Fatal("VerifyNSEC3Denial must reject iterations over the RFC 9276 cap")
	}

	// The RRSIG-gated and wildcard entry points reject as well (before crypto/hashing).
	proof := VerifyNSEC3DenialWithRRSIG("nx.example.com.", 1, over, nil, "example.com.", nil, 3)
	if proof == nil || proof.Error == "" || !strings.Contains(proof.Error, "9276") {
		t.Errorf("VerifyNSEC3DenialWithRRSIG should flag the iteration cap, got %+v", proof)
	}
	wc := VerifyWildcardDenial("nx.example.com.", 2, nil, over)
	if wc == nil || wc.Error == "" || !strings.Contains(wc.Error, "9276") {
		t.Errorf("VerifyWildcardDenial should flag the iteration cap, got %+v", wc)
	}

	// A compliant iteration count is not rejected by the cap (it fails later for
	// other reasons, but never with the cap error).
	ok := []dnspkg.NSEC3Record{{
		HashedOwner: strings.Repeat("A", 32), NextHashed: strings.Repeat("Z", 32),
		Algorithm: NSEC3HashSHA1, Salt: "", Iterations: 10, TypeBitmap: []string{"A"},
	}}
	if _, err := VerifyNSEC3Denial("nx.example.com.", 1, ok, "example.com.", 3); err != nil && strings.Contains(err.Error(), "9276") {
		t.Errorf("iterations=10 must not trip the cap: %v", err)
	}
}
