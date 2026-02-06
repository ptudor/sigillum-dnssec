package dns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testAnchors returns a RootAnchors fixture with both a valid and an expired anchor.
func testAnchors() *RootAnchors {
	expired := "2020-01-01T00:00:00Z"
	return &RootAnchors{
		Source:      "test",
		Zone:        ".",
		GeneratedAt: "2024-01-01T00:00:00Z",
		Anchors: []Anchor{
			{
				ID:             "KSK-2024",
				KeyTag:         20326,
				Algorithm:      8,
				AlgorithmName:  "RSASHA256",
				DigestType:     2,
				DigestTypeName: "SHA-256",
				Digest:         "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
				ValidFrom:      "2017-02-02T00:00:00Z",
				ValidUntil:     nil, // still valid
				PublicKey:      "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
				Flags:          257,
			},
			{
				ID:             "KSK-OLD",
				KeyTag:         19036,
				Algorithm:      8,
				AlgorithmName:  "RSASHA256",
				DigestType:     2,
				DigestTypeName: "SHA-256",
				Digest:         "49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5",
				ValidFrom:      "2010-07-15T00:00:00Z",
				ValidUntil:     &expired,
				PublicKey:      "oldkey",
				Flags:          257,
			},
		},
	}
}

func TestLoadAnchors(t *testing.T) {
	anchors := testAnchors()
	data, err := json.Marshal(anchors)
	if err != nil {
		t.Fatalf("failed to marshal test anchors: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "root-anchors.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	loaded, err := LoadAnchors(path)
	if err != nil {
		t.Fatalf("LoadAnchors() error: %v", err)
	}

	// Expired anchor should be filtered out
	if len(loaded.Anchors) != 1 {
		t.Errorf("expected 1 valid anchor, got %d", len(loaded.Anchors))
	}

	if loaded.Anchors[0].KeyTag != 20326 {
		t.Errorf("expected KeyTag 20326, got %d", loaded.Anchors[0].KeyTag)
	}

	if loaded.LoadedFrom != path {
		t.Errorf("LoadedFrom = %q, want %q", loaded.LoadedFrom, path)
	}
}

func TestLoadAnchors_FileNotFound(t *testing.T) {
	_, err := LoadAnchors("/nonexistent/path/anchors.json")
	if err == nil {
		t.Error("LoadAnchors() expected error for missing file")
	}
}

func TestLoadAnchors_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	_, err := LoadAnchors(path)
	if err == nil {
		t.Error("LoadAnchors() expected error for invalid JSON")
	}
}

func TestLoadAnchorsFromURL(t *testing.T) {
	anchors := testAnchors()
	data, err := json.Marshal(anchors)
	if err != nil {
		t.Fatalf("failed to marshal test anchors: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != UserAgent {
			t.Errorf("User-Agent = %q, want %q", r.Header.Get("User-Agent"), UserAgent)
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q, want %q", r.Header.Get("Accept"), "application/json")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	loaded, err := LoadAnchorsFromURL(server.URL)
	if err != nil {
		t.Fatalf("LoadAnchorsFromURL() error: %v", err)
	}

	if len(loaded.Anchors) != 1 {
		t.Errorf("expected 1 valid anchor, got %d", len(loaded.Anchors))
	}

	if loaded.LoadedFrom != server.URL {
		t.Errorf("LoadedFrom = %q, want %q", loaded.LoadedFrom, server.URL)
	}
}

func TestLoadAnchorsFromURL_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := LoadAnchorsFromURL(server.URL)
	if err == nil {
		t.Error("LoadAnchorsFromURL() expected error for 500 response")
	}
}

func TestLoadAnchorsWithFallback(t *testing.T) {
	anchors := testAnchors()
	data, err := json.Marshal(anchors)
	if err != nil {
		t.Fatalf("failed to marshal test anchors: %v", err)
	}

	// Set up HTTP server as fallback
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	}))
	defer server.Close()

	// File doesn't exist, should fall back to URL
	loaded, err := LoadAnchorsWithFallback("/nonexistent/path", server.URL)
	if err != nil {
		t.Fatalf("LoadAnchorsWithFallback() error: %v", err)
	}

	if len(loaded.Anchors) != 1 {
		t.Errorf("expected 1 valid anchor from URL fallback, got %d", len(loaded.Anchors))
	}
}

func TestLoadAnchorsWithFallback_FileFirst(t *testing.T) {
	anchors := testAnchors()
	data, err := json.Marshal(anchors)
	if err != nil {
		t.Fatalf("failed to marshal test anchors: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "root-anchors.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	// URL should NOT be called since file works
	urlCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		urlCalled = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	loaded, err := LoadAnchorsWithFallback(path, server.URL)
	if err != nil {
		t.Fatalf("LoadAnchorsWithFallback() error: %v", err)
	}

	if urlCalled {
		t.Error("URL should not have been called when file is available")
	}

	if loaded.LoadedFrom != path {
		t.Errorf("LoadedFrom = %q, want %q", loaded.LoadedFrom, path)
	}
}

func TestVerifyDNSKEYAgainstAnchor(t *testing.T) {
	anchor := Anchor{
		KeyTag:    20326,
		Algorithm: 8,
		PublicKey: "testkey",
	}

	tests := []struct {
		name     string
		dnskey   DNSKEYRecord
		expected bool
	}{
		{
			name:     "matching key tag and algorithm with pubkey",
			dnskey:   DNSKEYRecord{KeyTag: 20326, Algorithm: 8, PublicKey: "testkey"},
			expected: true,
		},
		{
			name:     "matching key tag and algorithm without pubkey match",
			dnskey:   DNSKEYRecord{KeyTag: 20326, Algorithm: 8, PublicKey: "otherkey"},
			expected: true, // still true - key tag + alg match is sufficient
		},
		{
			name:     "wrong key tag",
			dnskey:   DNSKEYRecord{KeyTag: 12345, Algorithm: 8, PublicKey: "testkey"},
			expected: false,
		},
		{
			name:     "wrong algorithm",
			dnskey:   DNSKEYRecord{KeyTag: 20326, Algorithm: 13, PublicKey: "testkey"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyDNSKEYAgainstAnchor(tt.dnskey, anchor)
			if result != tt.expected {
				t.Errorf("VerifyDNSKEYAgainstAnchor() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFindMatchingAnchor(t *testing.T) {
	anchors := []Anchor{
		{KeyTag: 20326, Algorithm: 8},
		{KeyTag: 19036, Algorithm: 8},
	}

	// Should find first matching anchor
	dnskey := DNSKEYRecord{KeyTag: 20326, Algorithm: 8}
	match := FindMatchingAnchor(dnskey, anchors)
	if match == nil {
		t.Fatal("FindMatchingAnchor() returned nil, expected match")
	}
	if match.KeyTag != 20326 {
		t.Errorf("matched anchor KeyTag = %d, want 20326", match.KeyTag)
	}

	// Should return nil for non-matching key
	dnskey2 := DNSKEYRecord{KeyTag: 65535, Algorithm: 13}
	match2 := FindMatchingAnchor(dnskey2, anchors)
	if match2 != nil {
		t.Errorf("FindMatchingAnchor() = %v, want nil", match2)
	}
}

func TestGetActiveAnchors(t *testing.T) {
	past := "2010-01-01T00:00:00Z"
	future := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	expired := "2020-01-01T00:00:00Z"
	farFuture := time.Now().Add(10 * 365 * 24 * time.Hour).Format(time.RFC3339)

	anchors := &RootAnchors{
		Anchors: []Anchor{
			{
				ID:        "active-no-expiry",
				KeyTag:    1,
				ValidFrom: past,
			},
			{
				ID:         "active-with-future-expiry",
				KeyTag:     2,
				ValidFrom:  past,
				ValidUntil: &future,
			},
			{
				ID:         "expired",
				KeyTag:     3,
				ValidFrom:  past,
				ValidUntil: &expired,
			},
			{
				ID:        "not-yet-valid",
				KeyTag:    4,
				ValidFrom: farFuture,
			},
		},
	}

	active := GetActiveAnchors(anchors)
	if len(active) != 2 {
		t.Fatalf("GetActiveAnchors() returned %d anchors, want 2", len(active))
	}

	tags := map[int]bool{}
	for _, a := range active {
		tags[a.KeyTag] = true
	}
	if !tags[1] || !tags[2] {
		t.Errorf("expected KeyTags 1 and 2 to be active, got %v", tags)
	}
}

func TestGetActiveAnchors_Nil(t *testing.T) {
	result := GetActiveAnchors(nil)
	if result != nil {
		t.Errorf("GetActiveAnchors(nil) = %v, want nil", result)
	}
}

func TestGetRootServers(t *testing.T) {
	servers := GetRootServers()
	if len(servers) != 13 {
		t.Errorf("GetRootServers() returned %d servers, want 13", len(servers))
	}

	// Verify first (a.root) and last (m.root)
	if servers[0] != "198.41.0.4" {
		t.Errorf("first root server = %q, want 198.41.0.4", servers[0])
	}
	if servers[12] != "202.12.27.33" {
		t.Errorf("last root server = %q, want 202.12.27.33", servers[12])
	}
}
