package dns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

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

	return &anchors, nil
}

// LoadAnchorsFromURL loads root trust anchors from a URL
func LoadAnchorsFromURL(url string) (*RootAnchors, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch anchors: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
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

// VerifyDNSKEYAgainstAnchor checks if a DNSKEY matches a trust anchor
func VerifyDNSKEYAgainstAnchor(dnskey DNSKEYRecord, anchor Anchor) bool {
	// Check key tag
	if int(dnskey.KeyTag) != anchor.KeyTag {
		return false
	}

	// Check algorithm
	if int(dnskey.Algorithm) != anchor.Algorithm {
		return false
	}

	// For anchors with public key, verify the key matches
	if anchor.PublicKey != "" && anchor.PublicKey == dnskey.PublicKey {
		return true
	}

	// Key tag and algorithm match
	return true
}

// FindMatchingAnchor finds an anchor that matches the given DNSKEY
func FindMatchingAnchor(dnskey DNSKEYRecord, anchors []Anchor) *Anchor {
	for i, anchor := range anchors {
		if VerifyDNSKEYAgainstAnchor(dnskey, anchor) {
			return &anchors[i]
		}
	}
	return nil
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
