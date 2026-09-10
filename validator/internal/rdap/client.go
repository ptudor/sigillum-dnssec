package rdap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// maxRDAPResponseBytes caps the RDAP response body we buffer (1 MiB). RDAP
// domain objects are small; anything larger is a misbehaving/hostile endpoint
// and is rejected, not parsed from its prefix (RDAYBLUEX-034).
const maxRDAPResponseBytes = 1 << 20

// errRedirectRefused marks a redirect the client refused to follow.
var errRedirectRefused = errors.New("RDAP redirect refused")

// Client is an RDAP client for querying domain secureDNS information.
//
// Every validation of the public service may trigger one GET to the
// configured RDAP origin, so the client is a blind server-side request
// surface (RDAYBLUEX-020). It therefore never follows a redirect (a
// compromised endpoint could otherwise steer it at loopback, link-local,
// private or metadata services), and when an egress policy is installed it
// applies that policy at the dial boundary to every address the endpoint's
// hostname resolves to — dialing only an address it checked, so a DNS
// rebinding between check and connect is impossible.
type Client struct {
	baseURL    string
	httpClient *http.Client
	egress     *dns.EgressPolicy
	// lookup resolves a hostname for the dial-boundary check; tests replace
	// it to model rebinding-style answers.
	lookup func(ctx context.Context, host string) ([]net.IP, error)
}

// NewClient creates a new RDAP client.
func NewClient(baseURL string, timeout time.Duration) *Client {
	// Normalize base URL (remove trailing slash)
	baseURL = strings.TrimSuffix(baseURL, "/")

	c := &Client{
		baseURL: baseURL,
		lookup: func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			ips := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, nil
		},
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy:                 nil, // never route the diagnostic egress through an environment proxy
		DialContext:           c.dialContext(dialer),
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	c.httpClient = &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return fmt.Errorf("%w: %s -> %s", errRedirectRefused, via[0].URL.Redacted(), req.URL.Redacted())
		},
	}
	return c
}

// SetEgressPolicy installs the destination policy applied at the dial
// boundary; nil permits every destination.
func (c *Client) SetEgressPolicy(p *dns.EgressPolicy) { c.egress = p }

// dialContext returns the transport dialer: the target host is resolved
// once, every resolved address is checked against the egress policy, and
// only a permitted address is dialed — the same one that was checked.
func (c *Client) dialContext(d *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("RDAP dial: %w", err)
		}
		var ips []net.IP
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			ips = []net.IP{ip}
		} else {
			ips, err = c.lookup(ctx, host)
			if err != nil {
				return nil, fmt.Errorf("RDAP dial: resolving %s: %w", host, err)
			}
		}
		var lastErr error
		for _, ip := range ips {
			if err := c.egress.PermitIP(ip); err != nil {
				lastErr = fmt.Errorf("RDAP dial: %w", err)
				continue
			}
			conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("RDAP dial: %s resolved to no address", host)
		}
		return nil, lastErr
	}
}

// QueryDomain queries RDAP for domain secureDNS information.
// Returns nil, nil if the domain is not found (404) - this is not an error.
// Returns nil, error on connection or parsing failures.
func (c *Client) QueryDomain(ctx context.Context, domain string) (*RDAPDomainResponse, error) {
	// Normalize domain (remove trailing dot, lowercase)
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)

	url := fmt.Sprintf("%s/domain/%s", c.baseURL, domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("User-Agent", dns.UserAgent)
	req.Header.Set("Accept", "application/rdap+json, application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	// 404 means domain not in RDAP - this is normal for many zones
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Bound the response so a compromised/oversized RDAP endpoint can't
	// exhaust memory, and reject an oversized body instead of parsing its
	// prefix (R-092, RDAYBLUEX-034).
	body, err := dns.ReadBodyLimited(resp.Body, maxRDAPResponseBytes, "RDAP")
	if err != nil {
		return nil, err
	}

	var rdapResp RDAPDomainResponse
	if err := json.Unmarshal(body, &rdapResp); err != nil {
		return nil, fmt.Errorf("parsing RDAP response: %w", err)
	}

	return &rdapResp, nil
}

// GetSecureDNS is a convenience method that returns just the secureDNS data.
// Returns nil, nil if domain not found or has no secureDNS data.
func (c *Client) GetSecureDNS(ctx context.Context, domain string) (*SecureDNS, error) {
	resp, err := c.QueryDomain(ctx, domain)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	return resp.SecureDNS, nil
}
