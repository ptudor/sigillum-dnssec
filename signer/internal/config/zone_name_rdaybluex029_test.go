package config

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// RDAYBLUEX-029: the managed-zone name grammar is enforced by one canonical
// validator with DNS wire limits, and everything it accepts is also accepted
// by the DNS parser (the state boundary's check).

func TestRDAYBLUEX029_ZoneNameGrammar(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	label64 := strings.Repeat("a", 64)
	// 253 characters: four 63-octet labels and one of 61, wire form 255.
	name253 := strings.Join([]string{label63, label63, label63, strings.Repeat("b", 61)}, ".")
	if len(name253) != 253 {
		t.Fatalf("fixture: %d", len(name253))
	}
	name254 := name253 + "c"
	cases := []struct {
		name   string
		domain string
		want   string // error substring, "" for accepted
	}{
		{"ordinary", "example.com", ""},
		{"trailing dot", "example.com.", ""},
		{"mixed case", "Example.COM", ""},
		{"63 octet label", label63 + ".example", ""},
		{"64 octet label", label64 + ".example", "above the 63 octet limit"},
		{"253 characters (255 wire octets)", name253, ""},
		{"253 characters with trailing dot", name253 + ".", ""},
		{"254 characters (256 wire octets)", name254, "above the 253 character limit"},
		{"leading hyphen", "-bad.example", "start or end with a hyphen"},
		{"trailing hyphen", "bad-.example", "start or end with a hyphen"},
		{"inner hyphen", "a-b.example", ""},
		{"underscore service label", "_acme-challenge.example.com", ""},
		{"underscore inside", "a_b.example", ""},
		{"empty label inside", "a..example", "empty label"},
		{"leading dot", ".example", "empty label"},
		{"double trailing dot", "example..", "empty label"},
		{"IDNA A-label", "xn--bcher-kva.example", ""},
		{"IDNA U-label", "bücher.example", "invalid character"},
		{"escaped octet", `a\046b.example`, "path separators or escapes"},
		{"space", "exa mple.com", "invalid character"},
		{"path separator", "a/b.example", "path separators"},
		{"traversal", "../example", "path separators"},
		{"root", ".", "root zone"},
		{"empty", "", "must not be empty"},
		{"single label", "localhost", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateDomainName(c.domain)
			if c.want == "" {
				if err != nil {
					t.Fatalf("%q must be accepted: %v", c.domain, err)
				}
				if _, ok := dns.IsDomainName(c.domain); !ok {
					t.Fatalf("%q is accepted by the config validator but not by the DNS parser", c.domain)
				}
				if _, ok := dns.IsDomainName(dns.Fqdn(c.domain)); !ok {
					t.Fatalf("%q (qualified) is accepted by the config validator but not by the DNS parser", c.domain)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%q must be rejected with %q, got %v", c.domain, c.want, err)
			}
		})
	}

	// Canonical identity still folds case and the trailing dot.
	if CanonicalZoneIdentity("Example.COM.") != "example.com" {
		t.Fatal("canonical identity")
	}
	// Config.Validate applies the same validator to every zone.
	c := DefaultConfig()
	c.OutputDir, c.DataDir = "/tmp/out", "/tmp/data"
	c.Zones[label64+".example"] = ZoneConfig{Path: "/tmp/zone.db"}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "63 octet limit") {
		t.Fatalf("Config.Validate must apply the grammar: %v", err)
	}
}
