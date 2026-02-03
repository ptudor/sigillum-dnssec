package validator

import (
	"strings"
)

// SplitIntoZoneHierarchy splits a domain name into its zone hierarchy
// e.g., "www.example.com" -> [".", "com.", "example.com.", "www.example.com."]
func SplitIntoZoneHierarchy(domain string) []string {
	// Normalize the domain
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return []string{"."}
	}

	// Ensure trailing dot
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}

	// Handle root zone
	if domain == "." {
		return []string{"."}
	}

	// Split into labels
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")

	// Build zone hierarchy from root to domain
	zones := []string{"."}

	for i := len(labels) - 1; i >= 0; i-- {
		zone := strings.Join(labels[i:], ".") + "."
		zones = append(zones, zone)
	}

	return zones
}

// GetParentZone returns the parent zone of a given zone
func GetParentZone(zone string) string {
	// Normalize
	zone = strings.ToLower(strings.TrimSpace(zone))
	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	// Root has no parent
	if zone == "." {
		return ""
	}

	// Remove first label
	idx := strings.Index(zone, ".")
	if idx == -1 || idx == len(zone)-1 {
		return "."
	}

	return zone[idx+1:]
}

// IsSubdomainOf checks if child is a subdomain of parent
func IsSubdomainOf(child, parent string) bool {
	// Normalize
	child = strings.ToLower(strings.TrimSpace(child))
	parent = strings.ToLower(strings.TrimSpace(parent))

	if !strings.HasSuffix(child, ".") {
		child = child + "."
	}
	if !strings.HasSuffix(parent, ".") {
		parent = parent + "."
	}

	// Root is parent of everything
	if parent == "." {
		return true
	}

	// Check if child ends with parent
	return strings.HasSuffix(child, "."+parent) || child == parent
}

// GetZoneLabels returns the number of labels in a zone
func GetZoneLabels(zone string) int {
	zone = strings.TrimSpace(zone)
	if !strings.HasSuffix(zone, ".") {
		zone = zone + "."
	}

	if zone == "." {
		return 0
	}

	return strings.Count(strings.TrimSuffix(zone, "."), ".") + 1
}

// NormalizeDomain normalizes a domain name to lowercase with trailing dot
func NormalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "."
	}
	if !strings.HasSuffix(domain, ".") {
		domain = domain + "."
	}
	return domain
}

// IsTLD returns true if the zone is a TLD (one label)
func IsTLD(zone string) bool {
	zone = NormalizeDomain(zone)
	if zone == "." {
		return false
	}
	return GetZoneLabels(zone) == 1
}

// IsRootZone returns true if the zone is the root zone
func IsRootZone(zone string) bool {
	zone = NormalizeDomain(zone)
	return zone == "."
}

// ExtractTLD extracts the TLD from a domain
func ExtractTLD(domain string) string {
	domain = NormalizeDomain(domain)
	if domain == "." {
		return "."
	}

	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(labels) == 0 {
		return "."
	}

	return labels[len(labels)-1] + "."
}

// IsRegistrableDomain returns true if the zone is a registrable domain
// (i.e., directly under a TLD, like "example.com" but not "www.example.com").
// This is a simplified check - doesn't handle complex TLDs like "co.uk".
func IsRegistrableDomain(zone string) bool {
	zone = NormalizeDomain(zone)
	if zone == "." {
		return false
	}
	// Registrable domains have exactly 2 labels (e.g., "example.com.")
	// This is a simple heuristic; real-world would need a public suffix list
	return GetZoneLabels(zone) == 2
}

// GetRegistrableDomain extracts the registrable domain from a full domain.
// e.g., "www.example.com." -> "example.com."
// Returns empty string for TLDs and root.
func GetRegistrableDomain(domain string) string {
	domain = NormalizeDomain(domain)
	labels := GetZoneLabels(domain)

	if labels < 2 {
		return ""
	}

	// Take the last 2 labels
	parts := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(parts) < 2 {
		return ""
	}

	return strings.Join(parts[len(parts)-2:], ".") + "."
}
