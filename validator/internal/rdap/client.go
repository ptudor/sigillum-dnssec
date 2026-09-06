package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// maxRDAPResponseBytes caps the RDAP response body we buffer (1 MiB). RDAP
// domain objects are small; anything larger is a misbehaving/hostile endpoint.
const maxRDAPResponseBytes = 1 << 20

// Client is an RDAP client for querying domain secureDNS information.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new RDAP client.
func NewClient(baseURL string, timeout time.Duration) *Client {
	// Normalize base URL (remove trailing slash)
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
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

	// Bound the response so a compromised/oversized RDAP endpoint can't exhaust
	// memory (mirrors the 1 MiB LimitReader used for trust anchors). R-092.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRDAPResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
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
