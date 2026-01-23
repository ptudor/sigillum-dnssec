package main

import (
	"testing"
)

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		// Valid domains
		{name: "simple domain", domain: "example.com", expected: true},
		{name: "subdomain", domain: "www.example.com", expected: true},
		{name: "deep subdomain", domain: "a.b.c.example.com", expected: true},
		{name: "with trailing dot", domain: "example.com.", expected: true},
		{name: "TLD only", domain: "com", expected: true},
		{name: "numeric subdomain", domain: "123.example.com", expected: true},
		{name: "hyphen in middle", domain: "my-domain.com", expected: true},
		{name: "alphanumeric", domain: "abc123.com", expected: true},
		{name: "single char labels", domain: "a.b.c", expected: true},
		{name: "underscore (DNS allows)", domain: "_dmarc.example.com", expected: true},

		// Invalid domains
		{name: "empty string", domain: "", expected: false},
		{name: "just dot", domain: ".", expected: false},
		{name: "double dot", domain: "example..com", expected: false},
		{name: "leading dot", domain: ".example.com", expected: false},
		{name: "hyphen at start", domain: "-example.com", expected: false},
		{name: "hyphen at end", domain: "example-.com", expected: false},
		{name: "label too long", domain: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", expected: false}, // 65 chars
		{name: "domain too long", domain: string(make([]byte, 254)) + ".com", expected: false},
		{name: "special chars", domain: "exam!ple.com", expected: false},
		{name: "space in domain", domain: "exam ple.com", expected: false},
		{name: "unicode", domain: "exämple.com", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("isValidDomain(%q) = %v, expected %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestIsValidDomainEdgeCases(t *testing.T) {
	// Test maximum valid label length (63 chars)
	maxLabel := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 63 chars
	if !isValidDomain(maxLabel + ".com") {
		t.Errorf("Domain with 63-char label should be valid")
	}

	// Test one over max label length (64 chars)
	overMaxLabel := maxLabel + "a" // 64 chars
	if isValidDomain(overMaxLabel + ".com") {
		t.Errorf("Domain with 64-char label should be invalid")
	}

	// Test a long domain with many short labels
	// Build a domain like a.a.a.a.a.a... up to near the 253 char limit
	longDomain := ""
	for i := 0; i < 125; i++ { // 125 * 2 = 250 chars ("a." repeated)
		longDomain += "a."
	}
	longDomain += "com" // Now ~253 chars
	// Just verify it doesn't panic
	_ = isValidDomain(longDomain)
}
