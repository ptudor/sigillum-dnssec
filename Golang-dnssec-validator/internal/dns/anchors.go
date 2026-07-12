package dns

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// pinnedAnchor is an authoritative IANA root trust anchor whose exact digest
// this validator ships pinned in the binary. Root-zone trust is established
// ONLY against these values, never against arbitrary loaded JSON (R-024).
type pinnedAnchor struct {
	KeyTag     int
	Algorithm  int
	DigestType int
	Digest     string // hex, compared case-insensitively
}

// pinnedRootAnchors is the set of authoritative IANA root KSK DS records this
// build accepts as a root of trust. It currently contains only KSK-2017
// (tag 20326), the active root KSK, whose SHA-256 DS digest is a stable,
// widely-published IANA constant.
//
// The pre-published successor KSK-2024 (tag 38696) is intentionally NOT pinned
// here: its authoritative digest is not shipped in this repository, and pinning
// an unverified security constant would be worse than failing closed. Before the
// scheduled 2026-10-11 root KSK rollover its authentic DS digest MUST be added
// below from authenticated IANA material. Until then the successor is not
// trusted for root validation (fail-closed) — strictly safer than trusting a
// digest supplied by an unauthenticated anchor file. See R-024/R-025.
var pinnedRootAnchors = []pinnedAnchor{
	{KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"},
}

// IsPinnedRootAnchor reports whether a exactly matches an authoritative pinned
// root anchor by key tag, algorithm, digest type, and digest (hex compared
// case-insensitively). Only pinned anchors may establish root trust — this is
// the authentication boundary that prevents an attacker-supplied anchor file or
// fetch from introducing its own root of trust (R-024).
func IsPinnedRootAnchor(a Anchor) bool {
	for _, p := range pinnedRootAnchors {
		if a.KeyTag == p.KeyTag && a.Algorithm == p.Algorithm &&
			a.DigestType == p.DigestType && strings.EqualFold(a.Digest, p.Digest) {
			return true
		}
	}
	return false
}

// hasPinnedRootAnchor reports whether any anchor in the set matches a pinned
// authoritative root anchor.
func hasPinnedRootAnchor(anchors []Anchor) bool {
	for _, a := range anchors {
		if IsPinnedRootAnchor(a) {
			return true
		}
	}
	return false
}

// digestHexLen maps a DS digest type to the exact hex-string length of its digest.
var digestHexLen = map[int]int{
	1: 40, // SHA-1   (20 bytes)
	2: 64, // SHA-256 (32 bytes)
	4: 96, // SHA-384 (48 bytes)
}

// validateAnchorStructure checks a single anchor's structural fields: supported
// digest type, and a digest that is valid hex of the exact length for that type.
// It does not check authenticity (the pinned-set gate does) or validity dates
// (the caller's time filter does).
func validateAnchorStructure(a Anchor) error {
	want, ok := digestHexLen[a.DigestType]
	if !ok {
		return fmt.Errorf("anchor %q (tag %d): unsupported digest type %d", a.ID, a.KeyTag, a.DigestType)
	}
	if len(a.Digest) != want {
		return fmt.Errorf("anchor %q (tag %d): digest length %d, want %d hex chars for digest type %d",
			a.ID, a.KeyTag, len(a.Digest), want, a.DigestType)
	}
	if _, err := hex.DecodeString(a.Digest); err != nil {
		return fmt.Errorf("anchor %q (tag %d): digest is not valid hex: %w", a.ID, a.KeyTag, err)
	}
	return nil
}

// finalizeAnchors applies the shared post-parse pipeline to a freshly decoded
// anchor document: validate the zone, drop expired anchors, structurally
// validate and de-duplicate the survivors, and require at least one authoritative
// pinned anchor so a wholesale swap to attacker material is refused. On success
// anchors.Anchors holds the filtered set and LoadedFrom records the source.
func finalizeAnchors(anchors *RootAnchors, source string) error {
	if anchors.Zone != "" && anchors.Zone != "." {
		return fmt.Errorf("anchors from %s declare zone %q, want the root zone \".\"", source, anchors.Zone)
	}

	// Filter to only valid anchors (ValidUntil is nil or in the future).
	validAnchors := make([]Anchor, 0, len(anchors.Anchors))
	now := time.Now()
	for _, a := range anchors.Anchors {
		if a.ValidUntil == nil {
			validAnchors = append(validAnchors, a)
			continue
		}
		validUntil, err := time.Parse(time.RFC3339, *a.ValidUntil)
		if err == nil && validUntil.After(now) {
			validAnchors = append(validAnchors, a)
		}
	}

	// Structurally validate and reject duplicate (key tag, digest type) records.
	seen := make(map[[2]int]bool, len(validAnchors))
	for _, a := range validAnchors {
		if err := validateAnchorStructure(a); err != nil {
			return fmt.Errorf("anchors from %s: %w", source, err)
		}
		key := [2]int{a.KeyTag, a.DigestType}
		if seen[key] {
			return fmt.Errorf("anchors from %s: duplicate anchor for key tag %d digest type %d", source, a.KeyTag, a.DigestType)
		}
		seen[key] = true
	}

	// Reject an anchor set that carries no authoritative pinned anchor (possible
	// wholesale swap). An empty set falls through to the URL fallback unchanged.
	if len(validAnchors) > 0 && !hasPinnedRootAnchor(validAnchors) {
		return fmt.Errorf("anchors from %s carry no authoritative pinned root KSK; refusing possible wholesale anchor swap", source)
	}

	anchors.Anchors = validAnchors
	anchors.LoadedFrom = source
	return nil
}

// LoadAnchors loads root trust anchors from a file.
func LoadAnchors(path string) (*RootAnchors, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read anchors file: %w", err)
	}

	var anchors RootAnchors
	if err := json.Unmarshal(data, &anchors); err != nil {
		return nil, fmt.Errorf("failed to parse anchors JSON: %w", err)
	}

	if err := finalizeAnchors(&anchors, path); err != nil {
		return nil, err
	}
	return &anchors, nil
}

// UserAgent for HTTP requests (visible in server logs)
const UserAgent = "TUDOR-DNSSEC-VALIDATOR/1.0 (ptudor.net)"

// anchorRedirectPolicy rejects security-relevant redirects when fetching anchors:
// a scheme downgrade (HTTPS to anything else) or a cross-origin (host change)
// redirect. This ensures validating the configured URL's scheme/host also
// constrains the URL actually fetched (R-024).
func anchorRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	orig := via[0].URL
	if orig.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refusing anchor redirect from %s to %s scheme (downgrade)", orig.Scheme, req.URL.Scheme)
	}
	// Same-origin only: host and port must match (a scheme upgrade on the same
	// host is allowed). Host includes an explicit port when present.
	if !strings.EqualFold(req.URL.Host, orig.Host) {
		return fmt.Errorf("refusing cross-origin anchor redirect from %q to %q", orig.Host, req.URL.Host)
	}
	return nil
}

// LoadAnchorsFromURL loads root trust anchors from a URL.
func LoadAnchorsFromURL(url string) (*RootAnchors, error) {
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: anchorRedirectPolicy,
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch anchors: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Limit response body to 1MB to prevent memory exhaustion
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var anchors RootAnchors
	if err := json.Unmarshal(data, &anchors); err != nil {
		return nil, fmt.Errorf("failed to parse anchors JSON: %w", err)
	}

	if err := finalizeAnchors(&anchors, url); err != nil {
		return nil, err
	}
	return &anchors, nil
}

// LoadAnchorsWithFallback tries to load from file first, then falls back to URL
func LoadAnchorsWithFallback(path, url string) (*RootAnchors, error) {
	// Try file first
	anchors, err := LoadAnchors(path)
	if err == nil && len(anchors.Anchors) > 0 {
		return anchors, nil
	}

	// Fall back to URL
	anchors, err = LoadAnchorsFromURL(url)
	if err != nil {
		return nil, fmt.Errorf("failed to load anchors from both file (%s) and URL (%s): %w", path, url, err)
	}

	return anchors, nil
}

// GetActiveAnchors returns anchors that are currently valid
func GetActiveAnchors(anchors *RootAnchors) []Anchor {
	if anchors == nil {
		return nil
	}

	active := make([]Anchor, 0)
	now := time.Now()

	for _, a := range anchors.Anchors {
		// Check ValidFrom
		validFrom, err := time.Parse(time.RFC3339, a.ValidFrom)
		if err != nil || now.Before(validFrom) {
			continue
		}

		// Check ValidUntil
		if a.ValidUntil != nil {
			validUntil, err := time.Parse(time.RFC3339, *a.ValidUntil)
			if err != nil || now.After(validUntil) {
				continue
			}
		}

		active = append(active, a)
	}

	return active
}
