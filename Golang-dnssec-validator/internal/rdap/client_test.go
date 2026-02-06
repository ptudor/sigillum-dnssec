package rdap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	// Should strip trailing slash from base URL
	c := NewClient("https://rdap.example.com/rdap/", 5*time.Second)
	if c.baseURL != "https://rdap.example.com/rdap" {
		t.Errorf("baseURL = %q, want trailing slash removed", c.baseURL)
	}

	// No trailing slash should be unchanged
	c2 := NewClient("https://rdap.example.com/rdap", 5*time.Second)
	if c2.baseURL != "https://rdap.example.com/rdap" {
		t.Errorf("baseURL = %q, want unchanged", c2.baseURL)
	}
}

func TestQueryDomain_Success(t *testing.T) {
	resp := RDAPDomainResponse{
		Handle:  "EXAMPLE-DOM",
		LDHName: "example.com",
		SecureDNS: &SecureDNS{
			DelegationSigned: true,
			DSData: []DSData{
				{
					KeyTag:     31406,
					Algorithm:  8,
					DigestType: 2,
					Digest:     "F78CF3344F72137235098ECBBD08947C2C9001C7F6A085A17F518B5D8F6B916D",
				},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request path
		if r.URL.Path != "/domain/example.com" {
			t.Errorf("request path = %q, want /domain/example.com", r.URL.Path)
		}

		// Verify headers
		accept := r.Header.Get("Accept")
		if accept != "application/rdap+json, application/json" {
			t.Errorf("Accept = %q, want rdap+json", accept)
		}

		w.Header().Set("Content-Type", "application/rdap+json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	result, err := client.QueryDomain(context.Background(), "example.com.")
	if err != nil {
		t.Fatalf("QueryDomain() error: %v", err)
	}

	if result == nil {
		t.Fatal("QueryDomain() returned nil")
	}

	if result.LDHName != "example.com" {
		t.Errorf("LDHName = %q, want example.com", result.LDHName)
	}

	if result.SecureDNS == nil {
		t.Fatal("SecureDNS is nil")
	}

	if !result.SecureDNS.DelegationSigned {
		t.Error("DelegationSigned = false, want true")
	}

	if len(result.SecureDNS.DSData) != 1 {
		t.Fatalf("DSData length = %d, want 1", len(result.SecureDNS.DSData))
	}

	if result.SecureDNS.DSData[0].KeyTag != 31406 {
		t.Errorf("DSData[0].KeyTag = %d, want 31406", result.SecureDNS.DSData[0].KeyTag)
	}
}

func TestQueryDomain_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	result, err := client.QueryDomain(context.Background(), "unknown.example")
	if err != nil {
		t.Fatalf("QueryDomain() error: %v (expected nil, nil for 404)", err)
	}
	if result != nil {
		t.Errorf("QueryDomain() = %v, want nil for 404", result)
	}
}

func TestQueryDomain_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	_, err := client.QueryDomain(context.Background(), "example.com")
	if err == nil {
		t.Error("QueryDomain() expected error for 500 response")
	}
}

func TestQueryDomain_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		w.Write([]byte("not json"))
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	_, err := client.QueryDomain(context.Background(), "example.com")
	if err == nil {
		t.Error("QueryDomain() expected error for invalid JSON")
	}
}

func TestQueryDomain_NormalizesInput(t *testing.T) {
	var receivedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/rdap+json")
		json.NewEncoder(w).Encode(RDAPDomainResponse{LDHName: "example.com"})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)

	// Should strip trailing dot and lowercase
	_, err := client.QueryDomain(context.Background(), "EXAMPLE.COM.")
	if err != nil {
		t.Fatalf("QueryDomain() error: %v", err)
	}

	if receivedPath != "/domain/example.com" {
		t.Errorf("request path = %q, want /domain/example.com (normalized)", receivedPath)
	}
}

func TestQueryDomain_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // delay to trigger cancel
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := client.QueryDomain(ctx, "example.com")
	if err == nil {
		t.Error("QueryDomain() expected error for canceled context")
	}
}

func TestGetSecureDNS_WithData(t *testing.T) {
	resp := RDAPDomainResponse{
		LDHName: "example.com",
		SecureDNS: &SecureDNS{
			DelegationSigned: true,
			DSData: []DSData{
				{KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "ABCD"},
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	secureDNS, err := client.GetSecureDNS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetSecureDNS() error: %v", err)
	}

	if secureDNS == nil {
		t.Fatal("GetSecureDNS() returned nil")
	}

	if !secureDNS.DelegationSigned {
		t.Error("DelegationSigned = false, want true")
	}
}

func TestGetSecureDNS_NoSecureDNS(t *testing.T) {
	resp := RDAPDomainResponse{
		LDHName:   "example.com",
		SecureDNS: nil,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rdap+json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	secureDNS, err := client.GetSecureDNS(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetSecureDNS() error: %v", err)
	}

	if secureDNS != nil {
		t.Errorf("GetSecureDNS() = %v, want nil when no secureDNS data", secureDNS)
	}
}

func TestGetSecureDNS_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	secureDNS, err := client.GetSecureDNS(context.Background(), "unknown.example")
	if err != nil {
		t.Fatalf("GetSecureDNS() error: %v", err)
	}

	if secureDNS != nil {
		t.Errorf("GetSecureDNS() = %v, want nil for 404 domain", secureDNS)
	}
}
