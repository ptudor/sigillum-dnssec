package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// DynadotClient talks to Dynadot's restful/v2 API.
//
// Authentication uses two separate credentials:
//   - api_key   → sent in the Authorization header as `Bearer <key>`
//   - api_secret → used as the HMAC-SHA256 key to sign each request, with
//     the signature placed in the `X-Signature` header.
//
// The signed string is `apiKey + "\n" + fullPathAndQuery + "\n" +
// xRequestId + "\n" + requestBody`, with xRequestId and body defaulting to
// empty strings when absent.
type DynadotClient struct {
	apiKey    string
	apiSecret string
	baseURL   string
	http      *http.Client
	limiter   *slidingLimiter
}

// NewDynadotClient validates credentials and constructs a client. The adapter
// requires both api_key and api_secret in the config file; there is no env
// fallback because the config file (mode 0640) is the stricter surface than
// rc.d / systemd unit files.
func NewDynadotClient(cfg *RegistrarDynadotConfig) (*DynadotClient, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("dynadot registrar is not enabled")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("dynadot api_key not set in config")
	}
	if cfg.APISecret == "" {
		return nil, fmt.Errorf("dynadot api_secret not set in config")
	}

	baseURL := "https://api.dynadot.com"
	if cfg.Sandbox {
		baseURL = "https://api-sandbox.dynadot.com"
	}

	timeout := cfg.Timeout.Duration
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &DynadotClient{
		apiKey:    cfg.APIKey,
		apiSecret: cfg.APISecret,
		baseURL:   baseURL,
		http:      &http.Client{Timeout: timeout},
		limiter:   newSlidingLimiter(),
	}, nil
}

// Name returns the adapter identifier used in config.
func (c *DynadotClient) Name() string { return "dynadot" }

// sign computes the Base64-encoded HMAC-SHA256 signature for one request.
// `path` must be exactly the `fullPathAndQuery` the server sees (including
// query string when present) — any mismatch produces an HTTP 401 on the
// server side because the signature won't match.
func (c *DynadotClient) sign(path, requestID, body string) string {
	stringToSign := c.apiKey + "\n" + path + "\n" + requestID + "\n" + body
	mac := hmac.New(sha256.New, []byte(c.apiSecret))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// newRequestID returns a RFC-4122-ish v4 UUID. Used as X-Request-ID so log
// correlation is possible without bringing in the google/uuid dep.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}

// apiError is the envelope Dynadot returns for every response, success or
// failure. `data` is delivered raw so each call-site can unmarshal its own
// specific shape without a second round-trip.
type apiError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// do executes a signed request against the given relative path. `body` can
// be nil for GET/DELETE. The returned `data` is whatever was inside the
// envelope's `data` field on success; errors carry Dynadot's message
// verbatim so operators can see exact text like "The domain doesn't
// support DNSSEC." in logs.
func (c *DynadotClient) do(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	// Gate every outgoing request through the sliding-scale limiter so
	// bursts self-throttle before Dynadot's 60/min cap kicks in with a 429.
	if c.limiter != nil {
		c.limiter.gate()
	}

	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
	}

	requestID := newRequestID()
	signature := c.sign(path, requestID, string(bodyBytes))

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if len(bodyBytes) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("X-Request-ID", requestID)
	req.Header.Set("X-Signature", signature)

	slog.Debug("[REGISTRAR] dynadot request", "method", method, "path", path, "request_id", requestID)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dynadot %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading dynadot response: %w", err)
	}

	// Some endpoints may return an empty 200 body; treat that as success.
	if len(bytes.TrimSpace(raw)) == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil, nil
	}

	var env apiError
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("dynadot response (HTTP %d): non-JSON body: %w", resp.StatusCode, err)
	}

	// The HTTP status code is authoritative; the envelope's `code` should
	// echo it. A mismatch means Dynadot changed their contract, which we
	// surface to operators so they notice.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		msg := env.Message
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return nil, fmt.Errorf("dynadot %s %s: HTTP %d: %s", method, path, resp.StatusCode, msg)
	}
	if env.Code != 0 && env.Code != http.StatusOK && env.Code != http.StatusCreated {
		return nil, fmt.Errorf("dynadot %s %s: envelope code %d: %s", method, path, env.Code, env.Message)
	}

	return env.Data, nil
}

// dynadotDSRecord matches the shape of a single entry in
// `data.dnssec_info_list` returned by GET /dnssec. Dynadot declares
// `algorithm` and `digest_type` as Strings in the docs, so we accept
// strings and convert to numeric DS fields on our side.
type dynadotDSRecord struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  string `json:"algorithm"`
	DigestType string `json:"digest_type"`
	Digest     string `json:"digest"`
}

// dynadotGetDNSSECData is the `data` portion of a get_dnssec response.
type dynadotGetDNSSECData struct {
	DNSSECInfoList []dynadotDSRecord `json:"dnssec_info_list"`
}

// dynadotSetDNSSECBody is the request body for PUT /dnssec. We only ever
// use the DS-form fields — the DNSKEY-form (flags + public_key) is
// intentionally unused because we compute DS ourselves from the live key.
type dynadotSetDNSSECBody struct {
	KeyTag     uint16 `json:"key_tag"`
	DigestType string `json:"digest_type"`
	Digest     string `json:"digest"`
	Algorithm  string `json:"algorithm"`
}

// dnssecPath returns the fully-qualified request path for a zone. The
// domain is lowercased because Dynadot rejects mixed-case input.
func dnssecPath(domain string) string {
	return "/restful/v2/domains/" + strings.ToLower(strings.TrimSuffix(domain, ".")) + "/dnssec"
}

// GetDS fetches the current DS record set from Dynadot.
func (c *DynadotClient) GetDS(ctx context.Context, domain string) ([]*dns.DS, error) {
	raw, err := c.do(ctx, http.MethodGet, dnssecPath(domain), nil)
	if err != nil {
		return nil, err
	}

	var payload dynadotGetDNSSECData
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &payload); err != nil {
			return nil, fmt.Errorf("parsing dnssec_info_list: %w", err)
		}
	}

	fqdn := dns.Fqdn(domain)
	out := make([]*dns.DS, 0, len(payload.DNSSECInfoList))
	for _, r := range payload.DNSSECInfoList {
		alg, err := parseDynadotUint8(r.Algorithm, "algorithm")
		if err != nil {
			return nil, err
		}
		dt, err := parseDynadotUint8(r.DigestType, "digest_type")
		if err != nil {
			return nil, err
		}
		out = append(out, &dns.DS{
			Hdr:        dns.RR_Header{Name: fqdn, Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
			KeyTag:     r.KeyTag,
			Algorithm:  alg,
			DigestType: dt,
			Digest:     strings.ToLower(r.Digest),
		})
	}
	return out, nil
}

// AddDS publishes DS records one at a time. Dynadot's PUT accepts a single
// record per request; we rely on the documented upsert-by-key_tag behavior
// observed in the legacy api3 endpoint and carried forward here. If a
// caller needs an atomic replace, they should use ReplaceDS instead.
func (c *DynadotClient) AddDS(ctx context.Context, domain string, records []*dns.DS) error {
	for _, ds := range records {
		body := dynadotSetDNSSECBody{
			KeyTag:     ds.KeyTag,
			DigestType: strconv.FormatUint(uint64(ds.DigestType), 10),
			Digest:     ds.Digest,
			Algorithm:  strconv.FormatUint(uint64(ds.Algorithm), 10),
		}
		if _, err := c.do(ctx, http.MethodPut, dnssecPath(domain), body); err != nil {
			return fmt.Errorf("set_dnssec (key_tag %d): %w", ds.KeyTag, err)
		}
		slog.Info("[REGISTRAR] dynadot DS published",
			"domain", domain, "key_tag", ds.KeyTag, "algorithm", ds.Algorithm, "digest_type", ds.DigestType)
	}
	return nil
}

// ReplaceDS wipes the DS set with DELETE then re-populates it. There is a
// brief (seconds) window with no DS at the parent; callers invoke this
// only at rollover completion, where the old DNSKEY is already retired
// from the zone and validators will accept bogus-during-transition.
//
// Passing an empty `records` slice performs just the DELETE — this is how
// `registrar clear` ends up on the wire.
func (c *DynadotClient) ReplaceDS(ctx context.Context, domain string, records []*dns.DS) error {
	if _, err := c.do(ctx, http.MethodDelete, dnssecPath(domain), nil); err != nil {
		return fmt.Errorf("clear_dnssec: %w", err)
	}
	slog.Info("[REGISTRAR] dynadot DS cleared", "domain", domain)

	if len(records) == 0 {
		return nil
	}
	return c.AddDS(ctx, domain, records)
}

// parseDynadotUint8 parses a Dynadot numeric-as-string field (their docs
// declare algorithm and digest_type as String) into the uint8 that DNS
// libraries expect. Accepts unquoted integers too, in case the API starts
// returning proper numbers later.
func parseDynadotUint8(s, field string) (uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("dynadot %s missing", field)
	}
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("dynadot %s %q: %w", field, s, err)
	}
	return uint8(n), nil
}
