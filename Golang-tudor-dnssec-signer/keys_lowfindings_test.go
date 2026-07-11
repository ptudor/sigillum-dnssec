package main

import (
	"testing"

	"github.com/miekg/dns"
)

// TestValidateLoadedKey (R-061): a loaded key must match the domain, role, and a
// supported algorithm, so a wrong file (bad owner, ZSK-in-KSK-slot, unsupported
// algorithm) is rejected rather than used silently.
func TestValidateLoadedKey(t *testing.T) {
	mk := func(name string, flags uint16, alg uint8) *dns.DNSKEY {
		return &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     flags,
			Protocol:  3,
			Algorithm: alg,
		}
	}

	cases := []struct {
		name    string
		key     *dns.DNSKEY
		domain  string
		keyType string
		wantErr bool
	}{
		{"valid KSK", mk("example.com.", 257, dns.ED25519), "example.com", "ksk", false},
		{"valid ZSK", mk("example.com.", 256, dns.ECDSAP256SHA256), "example.com", "zsk", false},
		{"case-insensitive owner", mk("EXAMPLE.COM.", 257, dns.ED25519), "example.com", "ksk", false},
		{"ZSK file in KSK slot", mk("example.com.", 256, dns.ED25519), "example.com", "ksk", true},
		{"KSK file in ZSK slot", mk("example.com.", 257, dns.ED25519), "example.com", "zsk", true},
		{"wrong owner", mk("evil.com.", 257, dns.ED25519), "example.com", "ksk", true},
		{"unsupported algorithm (RSA)", mk("example.com.", 257, dns.RSASHA256), "example.com", "ksk", true},
		{"unknown role", mk("example.com.", 257, dns.ED25519), "example.com", "csk", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateLoadedKey(c.key, c.domain, c.keyType)
			if (err != nil) != c.wantErr {
				t.Errorf("validateLoadedKey = %v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}
