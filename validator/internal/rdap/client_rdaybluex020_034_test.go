package rdap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// RDAYBLUEX-020: the RDAP client never follows redirects and applies the
// egress policy at its dial boundary to every resolved address.
// RDAYBLUEX-034: a body larger than the advertised maximum is rejected.

func rdapBody() string {
	return `{"handle":"X","ldhName":"example.com","secureDNS":{"delegationSigned":true,"dsData":[{"keyTag":1,"algorithm":13,"digestType":2,"digest":"` + strings.Repeat("AB", 32) + `"}]}}`
}

// captureServer records every request that reaches it.
func captureServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(rdapBody()))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestRDAYBLUEX020_RedirectsAreRefused(t *testing.T) {
	target, hits := captureServer(t)
	for _, code := range []int{301, 302, 307, 308} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target.URL+"/domain/example.com", code)
			}))
			defer src.Close()
			c := NewClient(src.URL, 2*time.Second) // no egress policy: loopback test doubles
			_, err := c.QueryDomain(context.Background(), "example.com")
			if !errors.Is(err, errRedirectRefused) {
				t.Fatalf("a %d redirect must be refused, got %v", code, err)
			}
		})
	}
	// Same-origin changed-path and self-redirect loops are refused too.
	var loop *httptest.Server
	loop = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, loop.URL+r.URL.Path+"/again", http.StatusFound)
	}))
	defer loop.Close()
	if _, err := NewClient(loop.URL, 2*time.Second).QueryDomain(context.Background(), "example.com"); !errors.Is(err, errRedirectRefused) {
		t.Fatalf("a same-origin redirect must be refused, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("no request may reach a redirect target, saw %d", hits.Load())
	}
}

func TestRDAYBLUEX020_EgressPolicyAtDial(t *testing.T) {
	srv, hits := captureServer(t)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	// A loopback literal under the public-only policy is refused before any
	// request is sent.
	c := NewClient(srv.URL, 2*time.Second)
	c.SetEgressPolicy(dns.PublicOnlyPolicy())
	if _, err := c.QueryDomain(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "egress policy") {
		t.Fatalf("a loopback destination must be refused, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("no request may reach a refused destination")
	}

	// A hostname that resolves to loopback (rebinding-style answer for a
	// public-looking name) is refused at dial time; a hostname resolving to
	// a private address likewise.
	for _, ip := range []string{host, "10.0.0.5", "fec0::1"} {
		c = NewClient("http://rdap.public.invalid:"+port, 2*time.Second)
		c.SetEgressPolicy(dns.PublicOnlyPolicy())
		c.lookup = func(ctx context.Context, h string) ([]net.IP, error) { return []net.IP{net.ParseIP(ip)}, nil }
		if _, err := c.QueryDomain(context.Background(), "example.com"); err == nil || !strings.Contains(err.Error(), "egress policy") {
			t.Fatalf("a hostname resolving to %s must be refused, got %v", ip, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatal("no request may reach a hostname-resolved refused destination")
	}

	// An operator allowlist admits the destination; the dialed address is
	// exactly the checked one.
	allow, _ := dns.ParseEgressAllowlist([]string{"127.0.0.0/8"})
	p := dns.PublicOnlyPolicy()
	p.Allow = allow
	c = NewClient("http://rdap.public.invalid:"+port, 2*time.Second)
	c.SetEgressPolicy(p)
	c.lookup = func(ctx context.Context, h string) ([]net.IP, error) { return []net.IP{net.ParseIP(host)}, nil }
	if _, err := c.QueryDomain(context.Background(), "example.com"); err != nil {
		t.Fatalf("an allowlisted destination must be reachable: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("exactly one request expected, saw %d", hits.Load())
	}
	// A deliberately internal deployment (AllowPrivate) reaches it too.
	c = NewClient(srv.URL, 2*time.Second)
	c.SetEgressPolicy(&dns.EgressPolicy{AllowPrivate: true})
	if _, err := c.QueryDomain(context.Background(), "example.com"); err != nil {
		t.Fatalf("AllowPrivate must permit the loopback double: %v", err)
	}
}

func TestRDAYBLUEX034_OversizedRDAPBodyRejected(t *testing.T) {
	limit := maxRDAPResponseBytes
	// A valid JSON object whose closing byte lands exactly at the limit,
	// followed by one extra byte: rejected as oversized.
	pad := func(total int) string {
		head := `{"handle":"`
		tail := `","ldhName":"example.com"}`
		return head + strings.Repeat("x", total-len(head)-len(tail)) + tail
	}
	cases := []struct {
		name    string
		body    string
		wantErr error
		wantOK  bool
	}{
		{"exactly at limit", pad(limit), nil, true},
		{"limit minus one", pad(limit - 1), nil, true},
		{"limit plus one", pad(limit) + "\n", dns.ErrResponseTooLarge, false},
		{"large non-JSON", strings.Repeat("z", limit+10), dns.ErrResponseTooLarge, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/rdap+json")
				_, _ = w.Write([]byte(c.body))
			}))
			defer srv.Close()
			resp, err := NewClient(srv.URL, 5*time.Second).QueryDomain(context.Background(), "example.com")
			if c.wantOK {
				if err != nil || resp == nil || resp.LDHName != "example.com" {
					t.Fatalf("body within the limit must parse: %v", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("expected %v, got %v", c.wantErr, err)
			}
		})
	}
	// A short read (connection dropped mid-body) is an error, not a parse of
	// the prefix.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100000")
		_, _ = w.Write([]byte(`{"handle":"X"`))
		panic(http.ErrAbortHandler)
	}))
	defer srv.Close()
	if _, err := NewClient(srv.URL, 2*time.Second).QueryDomain(context.Background(), "example.com"); err == nil {
		t.Fatal("a truncated body must be an error")
	}
}
