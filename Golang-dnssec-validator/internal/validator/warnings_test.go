package validator

import (
	"testing"

	dns "github.com/ptudor/dnssec-validator/internal/dns"
)

func TestCheckAlgorithmDeprecation(t *testing.T) {
	tests := []struct {
		name        string
		dnskeys     []dns.DNSKEYRecord
		wantCount   int
		wantContain string
	}{
		{
			name: "no deprecated algorithms",
			dnskeys: []dns.DNSKEYRecord{
				{Algorithm: 13}, // ECDSAP256SHA256
				{Algorithm: 8},  // RSASHA256
			},
			wantCount: 0,
		},
		{
			name: "RSASHA1 deprecated",
			dnskeys: []dns.DNSKEYRecord{
				{Algorithm: 5}, // RSASHA1
			},
			wantCount:   1,
			wantContain: "RSASHA1",
		},
		{
			name: "RSASHA1-NSEC3-SHA1 deprecated",
			dnskeys: []dns.DNSKEYRecord{
				{Algorithm: 7}, // RSASHA1-NSEC3-SHA1
			},
			wantCount:   1,
			wantContain: "RSASHA1-NSEC3-SHA1",
		},
		{
			name: "multiple deprecated - deduplicated",
			dnskeys: []dns.DNSKEYRecord{
				{Algorithm: 5},
				{Algorithm: 5}, // Duplicate
				{Algorithm: 7},
			},
			wantCount: 2, // One for alg 5, one for alg 7
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := CheckAlgorithmDeprecation(tt.dnskeys)
			if len(warnings) != tt.wantCount {
				t.Errorf("got %d warnings, want %d", len(warnings), tt.wantCount)
			}
			if tt.wantContain != "" && len(warnings) > 0 {
				found := false
				for _, w := range warnings {
					if contains(w, tt.wantContain) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("warnings should contain %q", tt.wantContain)
				}
			}
		})
	}
}

func TestCheckDigestTypeDeprecation(t *testing.T) {
	tests := []struct {
		name      string
		ds        []dns.DSRecord
		wantCount int
	}{
		{
			name: "SHA-256 not deprecated",
			ds: []dns.DSRecord{
				{DigestType: 2}, // SHA-256
			},
			wantCount: 0,
		},
		{
			name: "SHA-1 deprecated",
			ds: []dns.DSRecord{
				{DigestType: 1}, // SHA-1
			},
			wantCount: 1,
		},
		{
			name: "SHA-384 not deprecated",
			ds: []dns.DSRecord{
				{DigestType: 4}, // SHA-384
			},
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := CheckDigestTypeDeprecation(tt.ds)
			if len(warnings) != tt.wantCount {
				t.Errorf("got %d warnings, want %d", len(warnings), tt.wantCount)
			}
		})
	}
}

func TestCheckNSEC3Iterations(t *testing.T) {
	tests := []struct {
		name       string
		nsec3      []dns.NSEC3Record
		wantCount  int
		wantStrict bool // true if should mention "exceeds maximum"
	}{
		{
			name: "iterations 0 - ideal",
			nsec3: []dns.NSEC3Record{
				{Iterations: 0},
			},
			wantCount: 0,
		},
		{
			name: "iterations 10 - at ideal limit",
			nsec3: []dns.NSEC3Record{
				{Iterations: 10},
			},
			wantCount: 0,
		},
		{
			name: "iterations 50 - above ideal",
			nsec3: []dns.NSEC3Record{
				{Iterations: 50},
			},
			wantCount: 1,
		},
		{
			name: "iterations 100 - at max limit",
			nsec3: []dns.NSEC3Record{
				{Iterations: 100},
			},
			wantCount: 1,
		},
		{
			name: "iterations 150 - exceeds max",
			nsec3: []dns.NSEC3Record{
				{Iterations: 150},
			},
			wantCount:  1,
			wantStrict: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := CheckNSEC3Iterations(tt.nsec3)
			if len(warnings) != tt.wantCount {
				t.Errorf("got %d warnings, want %d", len(warnings), tt.wantCount)
			}
			if tt.wantStrict && len(warnings) > 0 {
				if !contains(warnings[0], "exceeds") {
					t.Errorf("warning should mention 'exceeds' for iterations > 100")
				}
			}
		})
	}
}

func TestCheckNSEC3OptOut(t *testing.T) {
	tests := []struct {
		name      string
		nsec3     []dns.NSEC3Record
		wantOptIn bool
	}{
		{
			name: "no opt-out",
			nsec3: []dns.NSEC3Record{
				{Flags: 0},
			},
			wantOptIn: false,
		},
		{
			name: "opt-out enabled",
			nsec3: []dns.NSEC3Record{
				{Flags: 1}, // Opt-out flag
			},
			wantOptIn: true,
		},
		{
			name:      "empty NSEC3",
			nsec3:     []dns.NSEC3Record{},
			wantOptIn: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			optOut, explanation := CheckNSEC3OptOut(tt.nsec3)
			if optOut != tt.wantOptIn {
				t.Errorf("got optOut=%v, want %v", optOut, tt.wantOptIn)
			}
			if optOut && explanation == "" {
				t.Error("opt-out should have explanation")
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
