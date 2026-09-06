package validator

import (
	"testing"
)

func TestSplitIntoZoneHierarchy(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected []string
	}{
		{
			name:     "simple domain",
			domain:   "example.com",
			expected: []string{".", "com.", "example.com."},
		},
		{
			name:     "subdomain",
			domain:   "www.example.com",
			expected: []string{".", "com.", "example.com.", "www.example.com."},
		},
		{
			name:     "deep subdomain",
			domain:   "a.b.c.example.com",
			expected: []string{".", "com.", "example.com.", "c.example.com.", "b.c.example.com.", "a.b.c.example.com."},
		},
		{
			name:     "with trailing dot",
			domain:   "example.com.",
			expected: []string{".", "com.", "example.com."},
		},
		{
			name:     "root zone",
			domain:   ".",
			expected: []string{"."},
		},
		{
			name:     "empty string",
			domain:   "",
			expected: []string{"."},
		},
		{
			name:     "TLD only",
			domain:   "com",
			expected: []string{".", "com."},
		},
		{
			name:     "uppercase domain",
			domain:   "WWW.EXAMPLE.COM",
			expected: []string{".", "com.", "example.com.", "www.example.com."},
		},
		{
			name:     "mixed case",
			domain:   "Www.ExAmPlE.cOm",
			expected: []string{".", "com.", "example.com.", "www.example.com."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SplitIntoZoneHierarchy(tt.domain)
			if len(result) != len(tt.expected) {
				t.Errorf("SplitIntoZoneHierarchy(%q) returned %d zones, expected %d: got %v, want %v",
					tt.domain, len(result), len(tt.expected), result, tt.expected)
				return
			}
			for i, zone := range result {
				if zone != tt.expected[i] {
					t.Errorf("SplitIntoZoneHierarchy(%q)[%d] = %q, expected %q",
						tt.domain, i, zone, tt.expected[i])
				}
			}
		})
	}
}

func TestGetParentZone(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		expected string
	}{
		{
			name:     "simple zone",
			zone:     "example.com.",
			expected: "com.",
		},
		{
			name:     "TLD",
			zone:     "com.",
			expected: ".",
		},
		{
			name:     "root zone",
			zone:     ".",
			expected: "",
		},
		{
			name:     "subdomain",
			zone:     "www.example.com.",
			expected: "example.com.",
		},
		{
			name:     "without trailing dot",
			zone:     "example.com",
			expected: "com.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetParentZone(tt.zone)
			if result != tt.expected {
				t.Errorf("GetParentZone(%q) = %q, expected %q", tt.zone, result, tt.expected)
			}
		})
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{
			name:     "simple domain",
			domain:   "example.com",
			expected: "example.com.",
		},
		{
			name:     "with trailing dot",
			domain:   "example.com.",
			expected: "example.com.",
		},
		{
			name:     "uppercase",
			domain:   "EXAMPLE.COM",
			expected: "example.com.",
		},
		{
			name:     "with spaces",
			domain:   "  example.com  ",
			expected: "example.com.",
		},
		{
			name:     "empty string",
			domain:   "",
			expected: ".",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("NormalizeDomain(%q) = %q, expected %q", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestIsSubdomainOf(t *testing.T) {
	tests := []struct {
		name     string
		child    string
		parent   string
		expected bool
	}{
		{
			name:     "direct child",
			child:    "example.com",
			parent:   "com",
			expected: true,
		},
		{
			name:     "grandchild",
			child:    "www.example.com",
			parent:   "com",
			expected: true,
		},
		{
			name:     "same domain",
			child:    "example.com",
			parent:   "example.com",
			expected: true,
		},
		{
			name:     "not subdomain",
			child:    "example.net",
			parent:   "com",
			expected: false,
		},
		{
			name:     "root is parent of all",
			child:    "example.com",
			parent:   ".",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSubdomainOf(tt.child, tt.parent)
			if result != tt.expected {
				t.Errorf("IsSubdomainOf(%q, %q) = %v, expected %v", tt.child, tt.parent, result, tt.expected)
			}
		})
	}
}

func TestIsTLD(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		expected bool
	}{
		{
			name:     "TLD",
			zone:     "com.",
			expected: true,
		},
		{
			name:     "second level domain",
			zone:     "example.com.",
			expected: false,
		},
		{
			name:     "root",
			zone:     ".",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsTLD(tt.zone)
			if result != tt.expected {
				t.Errorf("IsTLD(%q) = %v, expected %v", tt.zone, result, tt.expected)
			}
		})
	}
}
