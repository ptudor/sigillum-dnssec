package validator

import "testing"

// R-045: canonical ordering must compare unescaped, lowercased wire octets, not
// presentation strings, so escaped-octet owners order per RFC 4034 §6.1.
func TestR045_CanonicalOrderingEscapedOctets(t *testing.T) {
	// Case-insensitive equality.
	if compareCanonicalNames("Example.COM.", "example.com.") != 0 {
		t.Error("names differing only by case must be canonically equal")
	}
	// Shorter name (fewer labels) sorts first.
	if compareCanonicalNames("example.com.", "a.example.com.") >= 0 {
		t.Error("example.com. must sort before a.example.com.")
	}
	// An escaped decimal octet must compare by its byte value, not its literal
	// backslash-escape text. \065 == 'A' (0x41); as a raw label it lowercases to
	// 'a' (0x61). So "\065.com" and "a.com" denote the same wire label.
	if compareCanonicalNames("\\065.com.", "a.com.") != 0 {
		t.Errorf("escaped \\065 must equal 'a' after canonicalization")
	}
	// A literal backslash-zero-six-five string ("\065") vs "z": by wire octet the
	// first label is 'a' (0x61) which sorts before 'z' (0x7a).
	if compareCanonicalNames("\\065.com.", "z.com.") >= 0 {
		t.Error("canonical octet 'a' must sort before 'z'")
	}
}

// R-036: a single-record NSEC/NSEC3 chain whose next owner equals its own owner
// covers every name except the owner itself.
func TestR036_SingleRecordRingCoversAllButOwner(t *testing.T) {
	const owner = "apex.example."
	if !canonicallyBetween("absent.example.", owner, owner) {
		t.Error("a single-record NSEC (next==owner) must cover an absent name")
	}
	if !canonicallyBetween("other.example.", owner, owner) {
		t.Error("a single-record NSEC (next==owner) must cover another absent name")
	}
	if canonicallyBetween(owner, owner, owner) {
		t.Error("the owner itself must NOT be covered by its own interval")
	}

	// NSEC3 hash ring: single record whose next hash equals its own.
	const h = "ABCDEF"
	if !hashBetween("00XYZ0", h, h) {
		t.Error("a single-record NSEC3 ring (next==owner hash) must cover another hash")
	}
	if hashBetween(h, h, h) {
		t.Error("the owner hash must NOT be covered by its own interval")
	}
}
