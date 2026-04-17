package main

import (
	"testing"

	"github.com/miekg/dns"
)

// mkDS is a test helper that builds a DS record from primitive fields. The
// digest is intentionally accepted in either case — the equality helpers we
// exercise below normalize case on comparison.
func mkDS(keyTag uint16, alg, digestType uint8, digest string) *dns.DS {
	return &dns.DS{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
		KeyTag:     keyTag,
		Algorithm:  alg,
		DigestType: digestType,
		Digest:     digest,
	}
}

func TestCompareDSSets_InSync(t *testing.T) {
	a := mkDS(12345, 15, 2, "abcdef")
	b := mkDS(12345, 15, 2, "ABCDEF") // same record, upper-cased digest
	missing, extra := CompareDSSets([]*dns.DS{a}, []*dns.DS{b})
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("expected empty diff, got missing=%v extra=%v", missing, extra)
	}
}

func TestCompareDSSets_AdditionsAndRemovals(t *testing.T) {
	want := []*dns.DS{
		mkDS(11111, 15, 2, "aaaa"),
		mkDS(22222, 15, 2, "bbbb"),
	}
	have := []*dns.DS{
		mkDS(22222, 15, 2, "bbbb"),
		mkDS(33333, 15, 2, "cccc"),
	}
	missing, extra := CompareDSSets(want, have)
	if len(missing) != 1 || missing[0].KeyTag != 11111 {
		t.Fatalf("expected 11111 missing, got %v", missing)
	}
	if len(extra) != 1 || extra[0].KeyTag != 33333 {
		t.Fatalf("expected 33333 extra, got %v", extra)
	}
}

func TestRegistrarConfig_DigestType_Defaults(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want uint8
	}{
		{"zero_defaults_to_sha256", 0, 2},
		{"explicit_sha256", 2, 2},
		{"explicit_sha384", 4, 4},
		{"unknown_defaults_to_sha256", 1, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := RegistrarConfig{DigestTypeVal: tc.in}
			if got := rc.DigestType(); got != tc.want {
				t.Fatalf("DigestType(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestCheckDynadotEnvelope(t *testing.T) {
	okBody := []byte(`{"SetDnssecResponse":{"ResponseCode":0,"Status":"success"}}`)
	if err := checkDynadotEnvelope(okBody); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	errBody := []byte(`{"SetDnssecResponse":{"ResponseCode":-1,"Status":"error","Error":"bad api key"}}`)
	if err := checkDynadotEnvelope(errBody); err == nil {
		t.Fatal("expected error for ResponseCode=-1, got nil")
	}

	garbage := []byte(`not json`)
	if err := checkDynadotEnvelope(garbage); err == nil {
		t.Fatal("expected error for invalid json, got nil")
	}
}

// TestRegistrarFor_NotOptedIn confirms that zones without a registrar field
// behave exactly as before (nil adapter, no error).
func TestRegistrarFor_NotOptedIn(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Zones["example.com"] = ZoneConfig{Path: "/nonexistent"}
	reg, err := RegistrarFor(cfg, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg != nil {
		t.Fatalf("expected nil registrar for opt-out zone, got %q", reg.Name())
	}
}

// TestRegistrarFor_UnknownAdapter confirms misconfiguration is surfaced.
func TestRegistrarFor_UnknownAdapter(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Zones["example.com"] = ZoneConfig{Path: "/nonexistent", Registrar: "geocities"}
	if _, err := RegistrarFor(cfg, "example.com"); err == nil {
		t.Fatal("expected error for unknown registrar, got nil")
	}
}
