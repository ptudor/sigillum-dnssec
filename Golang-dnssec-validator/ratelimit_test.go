package main

import (
	"net/http/httptest"
	"testing"
)

func TestExtractClientIP_TrustedProxyUsesXFF(t *testing.T) {
	t.Cleanup(func() {
		_ = SetTrustedProxyCIDRs(defaultTrustedProxyCIDRs)
	})
	if err := SetTrustedProxyCIDRs([]string{"127.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxyCIDRs failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/validate", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.2")

	got := extractClientIP(req)
	if got != "203.0.113.7" {
		t.Fatalf("extractClientIP = %q, want %q", got, "203.0.113.7")
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
	req.RemoteAddr = "8.8.8.8:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Real-IP", "203.0.113.8")

	got := extractClientIP(req)
	if got != "8.8.8.8" {
		t.Fatalf("extractClientIP = %q, want %q", got, "8.8.8.8")
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
