package registrar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
)

// RDAYBLUEX-014: the registrar client never sends credentials over cleartext
// to a non-loopback host and never follows a redirect. RDAYBLUEX-034: an
// oversized response is rejected and stays an uncertain (dispatched) outcome.

func dynadotCfg(baseURL string, insecure bool) *config.RegistrarDynadotConfig {
	return &config.RegistrarDynadotConfig{Enabled: true, APIKey: "key-value", APISecret: "secret-value", BaseURL: baseURL, AllowInsecureBaseURL: insecure, Timeout: config.Duration{Duration: 2 * time.Second}}
}

func TestRDAYBLUEX014_ClientRefusesCleartextOverride(t *testing.T) {
	if _, err := NewDynadotClient(dynadotCfg("http://proxy.example.invalid", false)); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("a cleartext public override must be refused, got %v", err)
	}
	if _, err := NewDynadotClient(dynadotCfg("http://proxy.example.invalid", true)); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("the override never makes a public cleartext host acceptable, got %v", err)
	}
	if _, err := NewDynadotClient(dynadotCfg("http://127.0.0.1:8088", false)); err == nil {
		t.Fatal("a cleartext loopback override needs the explicit setting")
	}
	if _, err := NewDynadotClient(dynadotCfg("http://127.0.0.1:8088", true)); err != nil {
		t.Fatalf("a cleartext loopback test double with the explicit setting is allowed: %v", err)
	}
	if _, err := NewDynadotClient(dynadotCfg("https://proxy.example.invalid", false)); err != nil {
		t.Fatalf("an HTTPS override is allowed: %v", err)
	}
	if _, err := NewDynadotClient(dynadotCfg("proxy.example.invalid/api", false)); err == nil {
		t.Fatal("a relative override must be refused")
	}
}

func TestRDAYBLUEX014_RedirectsAreNeverFollowed(t *testing.T) {
	var leaked atomic.Int64
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Signature") != "" {
			leaked.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":200,"message":"Success","data":{"dnssec_info_list":[]}}`))
	}))
	defer capture.Close()

	for _, code := range []int{301, 302, 307, 308} {
		src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, capture.URL+r.URL.Path, code)
		}))
		c, err := NewDynadotClient(dynadotCfg(src.URL, true))
		if err != nil {
			t.Fatal(err)
		}
		// Every method, including the destructive ones, refuses the redirect.
		if _, err := c.GetDS(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "redirect refused") {
			t.Fatalf("%d: GET must refuse the redirect, got %v", code, err)
		}
		if err := c.AddDS(context.Background(), "example.com", []*dns.DS{mkDS(1, 15, 2, "aa")}); err == nil || !strings.Contains(err.Error(), "redirect refused") {
			t.Fatalf("%d: AddDS must refuse the redirect, got %v", code, err)
		}
		err = c.ReplaceDS(context.Background(), "example.com", []*dns.DS{mkDS(1, 15, 2, "aa")})
		if err == nil || !strings.Contains(err.Error(), "redirect refused") {
			t.Fatalf("%d: ReplaceDS must refuse the redirect before any DELETE, got %v", code, err)
		}
		var d *dispatchedError
		if !errors.As(err, &d) {
			t.Fatalf("%d: a refused redirect after dispatch is an uncertain outcome, got %T", code, err)
		}
		src.Close()
	}
	if leaked.Load() != 0 {
		t.Fatalf("credentials reached a redirect target %d time(s)", leaked.Load())
	}
}

func TestRDAYBLUEX034_OversizedRegistrarResponseIsDispatchedError(t *testing.T) {
	limit := maxDynadotResponseBytes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		head := `{"code":200,"message":"`
		tail := `","data":{"dnssec_info_list":[]}}`
		body := head + strings.Repeat("x", int(limit)-len(head)-len(tail)) + tail + "\n"
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c, err := NewDynadotClient(dynadotCfg(srv.URL, true))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetDS(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("a body one byte over the limit must be rejected as oversized, got %v", err)
	}
	var d *dispatchedError
	if !errors.As(err, &d) {
		t.Fatalf("an oversized response after dispatch stays an uncertain outcome, got %T", err)
	}
	// Exactly at the limit is accepted.
	at := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		head := `{"code":200,"message":"`
		tail := `","data":{"dnssec_info_list":[]}}`
		_, _ = w.Write([]byte(head + strings.Repeat("x", int(limit)-len(head)-len(tail)) + tail))
	}))
	defer at.Close()
	c, _ = NewDynadotClient(dynadotCfg(at.URL, true))
	if _, err := c.GetDS(context.Background(), "example.com"); err != nil {
		t.Fatalf("a body exactly at the limit must be accepted: %v", err)
	}
}
