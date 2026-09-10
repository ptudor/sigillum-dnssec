package validator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dnspkg "github.com/ptudor/sigillum-dnssec/validator/internal/dns"
	"github.com/ptudor/sigillum-dnssec/validator/internal/rdap"
)

// RDAYBLUEX-028: RDAP DS integers and digests are validated before they are
// narrowed to DNS wire widths; malformed records are excluded from matching
// and surfaced as a diagnostic, never wrapped into a value that could equal
// a real DNS DS tuple.

func TestRDAYBLUEX028_ValidateRDAPDS(t *testing.T) {
	sha256 := strings.Repeat("ab", 32)
	cases := []struct {
		name string
		ds   rdap.DSData
		want string // error substring, "" for valid
	}{
		{"valid SHA-256", rdap.DSData{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: sha256}, ""},
		{"valid SHA-384", rdap.DSData{KeyTag: 1, Algorithm: 14, DigestType: 4, Digest: strings.Repeat("cd", 48)}, ""},
		{"valid SHA-1", rdap.DSData{KeyTag: 1, Algorithm: 8, DigestType: 1, Digest: strings.Repeat("ef", 20)}, ""},
		{"negative key tag", rdap.DSData{KeyTag: -1, Algorithm: 13, DigestType: 2, Digest: sha256}, "keyTag"},
		{"key tag above maximum", rdap.DSData{KeyTag: 65536, Algorithm: 13, DigestType: 2, Digest: sha256}, "keyTag"},
		{"key tag wrapping to a real value", rdap.DSData{KeyTag: 65537, Algorithm: 13, DigestType: 2, Digest: sha256}, "keyTag"},
		{"algorithm wrapping", rdap.DSData{KeyTag: 1, Algorithm: 271, DigestType: 2, Digest: sha256}, "algorithm"},
		{"negative algorithm", rdap.DSData{KeyTag: 1, Algorithm: -13, DigestType: 2, Digest: sha256}, "algorithm"},
		{"digest type above maximum", rdap.DSData{KeyTag: 1, Algorithm: 13, DigestType: 258, Digest: sha256}, "digestType"},
		{"unknown digest type", rdap.DSData{KeyTag: 1, Algorithm: 13, DigestType: 3, Digest: sha256}, "not a supported"},
		{"odd-length digest", rdap.DSData{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: sha256[:63]}, "hexadecimal"},
		{"non-hex digest", rdap.DSData{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: strings.Repeat("zz", 32)}, "hexadecimal"},
		{"wrong digest length", rdap.DSData{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: strings.Repeat("ab", 20)}, "length"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, err := validateRDAPDS(c.ds)
			if c.want == "" {
				if err != nil {
					t.Fatalf("must be valid: %v", err)
				}
				if rec.Digest != strings.ToUpper(c.ds.Digest) {
					t.Fatalf("digest must be normalized to upper case, got %q", rec.Digest)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("must be rejected mentioning %q, got %v", c.want, err)
			}
		})
	}
}

// Through queryRDAPSecureDNS against a fake RDAP endpoint: a malformed record
// whose wrapped value would equal the real DNS DS never matches, the
// diagnostic names it, a valid control still matches, and the core status
// is untouched (the function only fills the RDAP diagnostic).
func TestRDAYBLUEX028_MalformedRDAPRecordsNeverMatch(t *testing.T) {
	digest := strings.Repeat("AB", 32)
	dnsDS := []dnspkg.DSRecord{{KeyTag: 1, Algorithm: 15, DigestType: 2, Digest: digest}}
	serve := func(dsData []map[string]any) *rdap.Client {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/rdap+json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"handle": "X", "ldhName": "example.com",
				"secureDNS": map[string]any{"delegationSigned": true, "dsData": dsData},
			})
		}))
		t.Cleanup(srv.Close)
		return rdap.NewClient(srv.URL, 2*time.Second)
	}
	v := NewValidator(2*time.Second, 5*time.Second, 2, &dnspkg.RootAnchors{Zone: "."}, "127.0.0.1")

	// keyTag 65537 wraps to 1, algorithm 271 wraps to 15: with narrowing these
	// would equal the DNS DS.
	v.SetRDAPClient(serve([]map[string]any{
		{"keyTag": 65537, "algorithm": 15, "digestType": 2, "digest": digest},
		{"keyTag": 1, "algorithm": 271, "digestType": 2, "digest": digest},
		{"keyTag": -65535, "algorithm": 15, "digestType": 2, "digest": digest},
		{"keyTag": 1, "algorithm": 15, "digestType": 2, "digest": "not hex"},
	}))
	res := v.queryRDAPSecureDNS(context.Background(), "example.com", dnsDS)
	if res.DSMatch == DSMatchFull || res.DSMatch == DSMatchPartial {
		t.Fatalf("malformed records must not match the DNS DS: %+v", res)
	}
	if len(res.DSData) != 0 {
		t.Fatalf("malformed records must be excluded, got %+v", res.DSData)
	}
	if !strings.Contains(res.Error, "4 malformed RDAP DS record(s)") || !strings.Contains(res.Error, "keyTag 65537") {
		t.Fatalf("the diagnostic must identify the rejected records: %q", res.Error)
	}

	// A valid control beside a malformed one still matches.
	v.SetRDAPClient(serve([]map[string]any{
		{"keyTag": 65537, "algorithm": 15, "digestType": 2, "digest": digest},
		{"keyTag": 1, "algorithm": 15, "digestType": 2, "digest": strings.ToLower(digest)},
	}))
	res = v.queryRDAPSecureDNS(context.Background(), "example.com", dnsDS)
	if res.DSMatch != DSMatchFull || len(res.DSData) != 1 || res.DSData[0].Digest != digest {
		t.Fatalf("the valid record must match with its digest normalized: %+v", res)
	}
	if !strings.Contains(res.Error, "1 malformed") {
		t.Fatalf("the rejected sibling must still be reported: %q", res.Error)
	}
}
