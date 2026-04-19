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
	apiKey        string
	apiSecret     string
	baseURL       string
	userAgent     string
	sendRequestID bool
	http          *http.Client
	limiter       *slidingLimiter
}

// defaultUserAgent returns the UA string used for Dynadot (and any future
// outbound HTTP from the signer) when the operator hasn't overridden it via
// config. Version is the ldflags-set build identifier; if it's the "dev"
// default we still emit something sensible so Dynadot's logs can tell us
// apart from a stock Go client.
func defaultUserAgent() string {
	v := Version
	if v == "" {
		v = "dev"
	}
	return "dnssec-tudor/" + v + " (+https://github.com/ptudor/dnssec-tudor)"
}

// NewDynadotClient validates credentials and constructs a client. The adapter
// requires both api_key and api_secret in the config file; there is no env
// fallback because the config file (mode 0640) is the stricter surface than
// rc.d / systemd unit files.
func NewDynadotClient(cfg *RegistrarDynadotConfig) (*DynadotClient, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("dynadot registrar is not enabled")
	}
	// Trim leading/trailing whitespace. Copy-paste from a web UI commonly
	// tacks on a newline, which silently breaks HMAC signatures — the
	// server computes HMAC over bytes-of-secret while ours has one extra
	// byte. Trimming here prevents that class of mystery 400s.
	apiKey := strings.TrimSpace(cfg.APIKey)
	apiSecret := strings.TrimSpace(cfg.APISecret)
	if apiKey == "" {
		return nil, fmt.Errorf("dynadot api_key not set in config")
	}
	if apiSecret == "" {
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

	ua := cfg.UserAgent
	if ua == "" {
		ua = defaultUserAgent()
	}

	return &DynadotClient{
		apiKey:        apiKey,
		apiSecret:     apiSecret,
		baseURL:       baseURL,
		userAgent:     ua,
		sendRequestID: cfg.SendRequestID,
		http:          &http.Client{Timeout: timeout},
		limiter:       newSlidingLimiter(),
	}, nil
}

// Name returns the adapter identifier used in config.
func (c *DynadotClient) Name() string { return "dynadot" }

// sign computes the Base64-encoded HMAC-SHA256 signature for one request.
// `path` must be exactly the `fullPathAndQuery` the server sees (including
// query string when present) — any mismatch produces "X-Signature invalid"
// (HTTP 400 with Dynadot's specific error body) on the server side.
//
// Emits a debug log of the string being signed when DEBUG is enabled so
// operators can eyeball byte-for-byte what went into the HMAC. The api key
// is shown in full (it's in the Authorization header anyway); the secret
// is never logged, only the resulting signature.
func (c *DynadotClient) sign(path, requestID, body string) string {
	stringToSign := c.apiKey + "\n" + path + "\n" + requestID + "\n" + body
	mac := hmac.New(sha256.New, []byte(c.apiSecret))
	mac.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	slog.Debug("[REGISTRAR] dynadot signing",
		"api_key_len", len(c.apiKey),
		"api_secret_len", len(c.apiSecret),
		"string_to_sign", stringToSign,
		"signature", sig)

	return sig
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

	// The request ID is used both in the signing string and (optionally)
	// on the wire as X-Request-ID. When sendRequestID is false, both are
	// empty — this matches what Dynadot computes when their case-sensitive
	// handler misses a non-empty header we sent, avoiding a whole class
	// of "signature invalid" errors.
	var requestID string
	if c.sendRequestID {
		requestID = newRequestID()
	}
	signature := c.sign(path, requestID, string(bodyBytes))

	// Pass a nil body rather than bytes.NewReader(nil) when there's nothing
	// to send — the latter causes Go to emit Content-Length: 0 even for
	// GET/DELETE, which some APIs (including Dynadot, suspected) treat as
	// a malformed request.
	var reqBody io.Reader
	if len(bodyBytes) > 0 {
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if len(bodyBytes) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if c.sendRequestID {
		req.Header.Set("X-Request-ID", requestID)
	}
	req.Header.Set("X-Signature", signature)
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	slog.Debug("[REGISTRAR] dynadot request",
		"method", method, "path", path,
		"request_id", requestID, "send_request_id_header", c.sendRequestID)

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

	// Always dump the raw response body at debug level on non-2xx — this
	// is what you want in front of you when triaging a Dynadot 400.
	if resp.StatusCode >= 400 {
		slog.Debug("[REGISTRAR] dynadot error response",
			"method", method, "path", path, "status", resp.StatusCode,
			"request_id", requestID, "body", truncate(string(raw), 1024))
	}

	var env apiError
	if err := json.Unmarshal(raw, &env); err != nil {
		// Surface the first chunk of the body so the operator has
		// something to grep for — opaque "non-JSON body" was useless.
		return nil, fmt.Errorf("dynadot %s %s (HTTP %d): non-JSON body: %q",
			method, path, resp.StatusCode, truncate(string(raw), 256))
	}

	// The HTTP status code is authoritative; the envelope's `code` should
	// echo it. A mismatch means Dynadot changed their contract, which we
	// surface to operators so they notice.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		msg := env.Message
		if msg == "" {
			// Fall back to a truncated raw body so HTTP 400s without a
			// structured "message" field still tell the operator what
			// Dynadot actually said. Stock http.StatusText was useless.
			msg = truncate(strings.TrimSpace(string(raw)), 256)
			if msg == "" {
				msg = http.StatusText(resp.StatusCode)
			}
		}
		return nil, fmt.Errorf("dynadot %s %s: HTTP %d: %s", method, path, resp.StatusCode, msg)
	}
	if env.Code != 0 && env.Code != http.StatusOK && env.Code != http.StatusCreated {
		return nil, fmt.Errorf("dynadot %s %s: envelope code %d: %s", method, path, env.Code, env.Message)
	}

	return env.Data, nil
}

// truncate returns s trimmed to at most max runes, with an ellipsis marker
// appended when truncation occurred. Used for including upstream-body
// excerpts in error strings without flooding logs on a huge HTML error page.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…[truncated]"
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
