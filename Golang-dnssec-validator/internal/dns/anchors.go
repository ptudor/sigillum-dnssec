package dns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// knownRootKSKTags are the IANA root-zone KSK key tags this validator
// recognizes: 20326 (KSK-2017, the currently-active root KSK) and 38696
// (KSK-2024, the pre-published successor). At least one loaded anchor must
// carry one of these tags, so a wholesale swap to an attacker-supplied anchor
// set is refused as a sanity floor. This is defense-in-depth: the primary check
// remains recomputing the DS from the live root DNSKEY and requiring a digest
// match. A future root KSK rollover requires adding the new tag here. R-087.
var knownRootKSKTags = map[int]bool{
	20326: true,
	38696: true,
}

// hasKnownRootTag reports whether any anchor carries a recognized root KSK tag.
func hasKnownRootTag(anchors []Anchor) bool {
	for _, a := range anchors {
		if knownRootKSKTags[a.KeyTag] {
			return true
		}
	}
	return false
}

// LoadAnchors loads root trust anchors from a file
func LoadAnchors(path string) (*RootAnchors, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read anchors file: %w", err)
	}

	var anchors RootAnchors
	if err := json.Unmarshal(data, &anchors); err != nil {
		return nil, fmt.Errorf("failed to parse anchors JSON: %w", err)
	}

	// Filter to only valid anchors (ValidUntil is nil or in the future)
	validAnchors := make([]Anchor, 0)
	now := time.Now()
	for _, a := range anchors.Anchors {
		if a.ValidUntil == nil {
			validAnchors = append(validAnchors, a)
		} else {
			validUntil, err := time.Parse(time.RFC3339, *a.ValidUntil)
			if err == nil && validUntil.After(now) {
				validAnchors = append(validAnchors, a)
			}
		}
	}
	anchors.Anchors = validAnchors
	anchors.LoadedFrom = path

	// Reject an anchor set whose keys are all unrecognized (possible swap); an
	// empty set falls through to the URL fallback unchanged.
	if len(validAnchors) > 0 && !hasKnownRootTag(validAnchors) {
		return nil, fmt.Errorf("anchors from %s carry no known root KSK key tag; refusing possible wholesale anchor swap", path)
	}

	return &anchors, nil
}

// UserAgent for HTTP requests (visible in server logs)
const UserAgent = "TUDOR-DNSSEC-VALIDATOR/1.0 (ptudor.net)"

// LoadAnchorsFromURL loads root trust anchors from a URL
func LoadAnchorsFromURL(url string) (*RootAnchors, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
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

	// Filter to only valid anchors
	validAnchors := make([]Anchor, 0)
	now := time.Now()
	for _, a := range anchors.Anchors {
		if a.ValidUntil == nil {
			validAnchors = append(validAnchors, a)
		} else {
			validUntil, err := time.Parse(time.RFC3339, *a.ValidUntil)
			if err == nil && validUntil.After(now) {
				validAnchors = append(validAnchors, a)
			}
		}
	}
	anchors.Anchors = validAnchors
	anchors.LoadedFrom = url

	if len(validAnchors) > 0 && !hasKnownRootTag(validAnchors) {
		return nil, fmt.Errorf("anchors from %s carry no known root KSK key tag; refusing possible wholesale anchor swap", url)
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
