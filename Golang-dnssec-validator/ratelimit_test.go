package main

import (
	"net/http/httptest"
	"testing"
)

func TestExtractClientIP_TrustedProxyUsesRightmostUntrustedXFF(t *testing.T) {
	t.Cleanup(func() {
		_ = SetTrustedProxyCIDRs(defaultTrustedProxyCIDRs)
	})
	if err := SetTrustedProxyCIDRs([]string{"127.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxyCIDRs failed: %v", err)
	}

	// The remote client spoofed a leftmost entry; our reverse proxy (127.0.0.1)
	// appended the real peer 203.0.113.7. The rightmost untrusted entry wins, and
	// the spoofed 1.2.3.4 must be ignored.
	req := httptest.NewRequest("GET", "/api/validate", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 203.0.113.7")

	got := extractClientIP(req)
	if got != "203.0.113.7" {
		t.Fatalf("extractClientIP = %q, want %q (spoofed leftmost must be ignored)", got, "203.0.113.7")
	}
}

func TestExtractClientIP_SkipsTrustedProxyHops(t *testing.T) {
	t.Cleanup(func() {
		_ = SetTrustedProxyCIDRs(defaultTrustedProxyCIDRs)
	})
	// 10.0.0.0/8 is an internal proxy tier; loopback is the edge proxy.
	if err := SetTrustedProxyCIDRs([]string{"127.0.0.0/8", "10.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxyCIDRs failed: %v", err)
	}

	// client -> edge(appends 198.51.100.9) -> internal(appends 10.0.0.2) -> us.
	req := httptest.NewRequest("GET", "/api/validate", nil)
	req.RemoteAddr = "10.0.0.5:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.9, 10.0.0.2")

	got := extractClientIP(req)
	if got != "198.51.100.9" {
		t.Fatalf("extractClientIP = %q, want %q (trusted hops must be skipped)", got, "198.51.100.9")
	}
}

func TestExtractClientIP_FallsBackToXRealIP(t *testing.T) {
	t.Cleanup(func() {
		_ = SetTrustedProxyCIDRs(defaultTrustedProxyCIDRs)
	})
	if err := SetTrustedProxyCIDRs([]string{"127.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxyCIDRs failed: %v", err)
	}

	// No usable XFF (only a trusted hop); X-Real-IP set by the proxy wins.
	req := httptest.NewRequest("GET", "/api/validate", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "203.0.113.42")

	got := extractClientIP(req)
	if got != "203.0.113.42" {
		t.Fatalf("extractClientIP = %q, want %q", got, "203.0.113.42")
	}
}

func TestExtractClientIP_UntrustedProxyIgnoresXFF(t *testing.T) {
	t.Cleanup(func() {
		_ = SetTrustedProxyCIDRs(defaultTrustedProxyCIDRs)
	})
	if err := SetTrustedProxyCIDRs([]string{"127.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxyCIDRs failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/validate", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Real-IP", "203.0.113.8")

	got := extractClientIP(req)
	if got != "203.0.113.9" {
		t.Fatalf("extractClientIP = %q, want %q", got, "203.0.113.9")
	}
}

func TestSetTrustedProxyCIDRsRejectsInvalidCIDR(t *testing.T) {
	t.Cleanup(func() {
		_ = SetTrustedProxyCIDRs(defaultTrustedProxyCIDRs)
	})

	if err := SetTrustedProxyCIDRs([]string{"invalid"}); err == nil {
		t.Fatal("SetTrustedProxyCIDRs expected error for invalid CIDR")
	}
}
