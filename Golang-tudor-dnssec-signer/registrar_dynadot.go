package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DynadotClient talks to Dynadot's api3.json public API.
//
// The API accepts the credential as a `key` query parameter. The client is
// careful never to log the full URL so the API key doesn't leak through
// structured logs — only the command name and domain are logged.
type DynadotClient struct {
	apiKey   string
	endpoint string
	http     *http.Client
}

// NewDynadotClient constructs a client from a RegistrarDynadotConfig. It
// resolves the API key from config or the DYNADOT_API_KEY environment
// variable and returns an error if neither source produces a value.
func NewDynadotClient(cfg *RegistrarDynadotConfig) (*DynadotClient, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("dynadot registrar is not enabled")
	}

	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("DYNADOT_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("dynadot api_key not set (config or DYNADOT_API_KEY env)")
	}

	endpoint := "https://api.dynadot.com/api3.json"
	if cfg.Sandbox {
		endpoint = "https://api-sandbox.dynadot.com/api3.json"
	}

	timeout := cfg.Timeout.Duration
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &DynadotClient{
		apiKey:   apiKey,
		endpoint: endpoint,
		http:     &http.Client{Timeout: timeout},
	}, nil
}

// Name returns the adapter identifier used in config.
func (c *DynadotClient) Name() string { return "dynadot" }

// dynadotEnvelope is the minimal wrapper Dynadot returns for every call. The
// exact response-name key (SetDnssecResponse, ClearDnssecResponse, etc.) is
// command-specific; we decode twice: once for the top-level envelope, once
// for the inner body when we need the DS list.
type dynadotEnvelope struct {
	ResponseCode int    `json:"ResponseCode"`
	Status       string `json:"Status"`
	Error        string `json:"Error"`
}

// dynadotGetDNSSECResponse matches the structure of a successful get_dnssec
// reply. Dynadot's JSON wraps content under "GetDnssecResponse" ->
// "GetDnssecContent" with DS / DNSKEY arrays; field casing in the docs is
// inconsistent, so we accept common variants.
type dynadotGetDNSSECResponse struct {
	GetDnssecResponse struct {
		ResponseCode int    `json:"ResponseCode"`
		Status       string `json:"Status"`
		Error        string `json:"Error"`
		Content      struct {
			DSRecords []struct {
				KeyTag     uint16 `json:"key_tag"`
				Algorithm  uint8  `json:"algorithm"`
				DigestType uint8  `json:"digest_type"`
				Digest     string `json:"digest"`
			} `json:"ds_records"`
		} `json:"GetDnssecContent"`
	} `json:"GetDnssecResponse"`
}

// call executes a Dynadot command with the given parameters. `params` must
// NOT contain the `key` or `command` fields — those are added here. The
// returned body bytes are the full response for command-specific decoding;
// the envelope check is performed here so callers only handle command-
// specific fields.
func (c *DynadotClient) call(ctx context.Context, command string, params url.Values) ([]byte, error) {
	q := url.Values{}
	q.Set("key", c.apiKey)
	q.Set("command", command)
	for k, v := range params {
		for _, vv := range v {
			q.Add(k, vv)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}

	// Intentionally log only command + domain — never the URL/params, which
	// include the API key.
	slog.Debug("[REGISTRAR] dynadot call", "command", command, "domain", params.Get("domain_name"))

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dynadot %s: %w", command, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading dynadot response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dynadot %s: HTTP %d", command, resp.StatusCode)
	}

	// Dynadot responses share a common shape for success/failure.
	// We best-effort decode the envelope from whichever top-level key is
	// present (e.g. SetDnssecResponse, ClearDnssecResponse). Any decode
	// failure here is non-fatal; we then try a structural walk.
	if err := checkDynadotEnvelope(body); err != nil {
		return nil, fmt.Errorf("dynadot %s: %w", command, err)
	}

	return body, nil
}

// checkDynadotEnvelope parses the top-level response object, locates the
// single child object (the *Response wrapper), and validates ResponseCode/
// Status/Error inside it. This matches Dynadot's JSON shape without our
// needing to know every command's exact wrapper name.
func checkDynadotEnvelope(body []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return fmt.Errorf("invalid json: %w", err)
	}
	for _, raw := range top {
		var env dynadotEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		if env.Status == "" && env.ResponseCode == 0 {
			// Could be a content object rather than the header — keep looking.
			continue
		}
		if env.ResponseCode != 0 || (env.Status != "" && !strings.EqualFold(env.Status, "success")) {
			msg := env.Error
			if msg == "" {
				msg = fmt.Sprintf("response_code=%d status=%q", env.ResponseCode, env.Status)
			}
			return fmt.Errorf("%s", msg)
		}
		return nil
	}
	return fmt.Errorf("no response envelope found in dynadot reply")
}

// setDS publishes one DS record via set_dnssec. Dynadot's set_dnssec is
// additive when called in DS form — existing DS records remain in place.
func (c *DynadotClient) setDS(ctx context.Context, domain string, ds *dns.DS) error {
	params := url.Values{}
	params.Set("domain_name", domain)
	params.Set("key_tag", fmt.Sprintf("%d", ds.KeyTag))
	params.Set("algorithm", fmt.Sprintf("%d", ds.Algorithm))
	params.Set("digest_type", fmt.Sprintf("%d", ds.DigestType))
	params.Set("digest", ds.Digest)
	_, err := c.call(ctx, "set_dnssec", params)
	return err
}

// AddDS publishes DS records additively. Returns early on the first error;
// partial success is logged so operators know which records went through.
func (c *DynadotClient) AddDS(ctx context.Context, domain string, records []*dns.DS) error {
	for _, ds := range records {
		if err := c.setDS(ctx, domain, ds); err != nil {
			return fmt.Errorf("set_dnssec (key_tag %d): %w", ds.KeyTag, err)
		}
		slog.Info("[REGISTRAR] dynadot DS added", "domain", domain, "key_tag", ds.KeyTag, "digest_type", ds.DigestType)
	}
	return nil
}

// ReplaceDS clears existing DS records and publishes the desired set. This
// has a brief (seconds) window with no DS present; callers use this only
// when that window is acceptable (e.g. rollover complete, where the old
// DNSKEY is already retired from the zone).
func (c *DynadotClient) ReplaceDS(ctx context.Context, domain string, records []*dns.DS) error {
	params := url.Values{}
	params.Set("domain_name", domain)
	if _, err := c.call(ctx, "clear_dnssec", params); err != nil {
		return fmt.Errorf("clear_dnssec: %w", err)
	}
	slog.Info("[REGISTRAR] dynadot DS cleared", "domain", domain)

	if err := c.AddDS(ctx, domain, records); err != nil {
		return fmt.Errorf("replace_ds publish step: %w", err)
	}
	return nil
}

// GetDS retrieves the DS records currently published at Dynadot.
func (c *DynadotClient) GetDS(ctx context.Context, domain string) ([]*dns.DS, error) {
	params := url.Values{}
	params.Set("domain_name", domain)
	body, err := c.call(ctx, "get_dnssec", params)
	if err != nil {
		return nil, err
	}

	var parsed dynadotGetDNSSECResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decoding get_dnssec response: %w", err)
	}

	fqdn := dns.Fqdn(domain)
	out := make([]*dns.DS, 0, len(parsed.GetDnssecResponse.Content.DSRecords))
	for _, r := range parsed.GetDnssecResponse.Content.DSRecords {
		ds := &dns.DS{
			Hdr:        dns.RR_Header{Name: fqdn, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
			KeyTag:     r.KeyTag,
			Algorithm:  r.Algorithm,
			DigestType: r.DigestType,
			Digest:     strings.ToLower(r.Digest),
		}
		out = append(out, ds)
	}
	return out, nil
}
