package config

import (
	"strings"
	"testing"
)

// RDAYBLUEX-020: the RDAP base URL is validated as an absolute HTTPS URL
// without userinfo, query, fragment or ambiguous path; cleartext is allowed
// only for a loopback host behind the explicit development override.
func TestRDAYBLUEX020_ValidateRDAPBaseURL(t *testing.T) {
	cases := []struct {
		name   string
		raw    string
		allow  bool
		wantOK bool
		want   string
	}{
		{"empty disables RDAP", "", false, true, ""},
		{"https", "https://rdap.example.invalid/rdap", false, true, ""},
		{"https with trailing slash", "https://rdap.example.invalid/rdap/", false, true, ""},
		{"cleartext", "http://rdap.example.invalid/rdap", false, false, "https"},
		{"cleartext with override but public host", "http://rdap.example.invalid/rdap", true, false, "loopback"},
		{"cleartext loopback without override", "http://127.0.0.1:8080/rdap", false, false, "https"},
		{"cleartext loopback with override", "http://127.0.0.1:8080/rdap", true, true, ""},
		{"cleartext localhost with override", "http://localhost:8080/", true, true, ""},
		{"cleartext v6 loopback with override", "http://[::1]:8080/", true, true, ""},
		{"relative", "/rdap", false, false, "absolute"},
		{"no scheme", "rdap.example.invalid/rdap", false, false, "absolute"},
		{"userinfo", "https://user:pw@rdap.example.invalid/rdap", false, false, "userinfo"},
		{"query", "https://rdap.example.invalid/rdap?x=1", false, false, "query"},
		{"fragment", "https://rdap.example.invalid/rdap#f", false, false, "fragment"},
		{"dot-dot path", "https://rdap.example.invalid/a/../rdap", false, false, ".."},
		{"other scheme", "ftp://rdap.example.invalid/rdap", false, false, "scheme"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateRDAPBaseURL(c.raw, c.allow)
			if c.wantOK {
				if err != nil {
					t.Fatalf("%q must be accepted: %v", c.raw, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%q must be rejected mentioning %q, got %v", c.raw, c.want, err)
			}
		})
	}
	// Config.Validate applies it.
	cfg := DefaultConfig()
	cfg.RDAPBaseURL = "http://rdap.example.invalid/rdap"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "rdap_base_url") {
		t.Fatalf("Validate must reject a cleartext RDAP URL, got %v", err)
	}
	cfg.RDAPBaseURL = "http://127.0.0.1:9/rdap"
	cfg.RDAPAllowInsecureLoopback = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate must accept a loopback cleartext URL with the override: %v", err)
	}
}
