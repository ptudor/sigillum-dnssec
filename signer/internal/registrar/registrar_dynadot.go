package registrar

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
)

// sharedDynadotLimiter is the process-wide Dynadot rate limiter. Shared by
// every DynadotClient so the sliding window spans operations (R-073).
var sharedDynadotLimiter = newWindowLimiter()

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
	limiter       *windowLimiter
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
	return "sigillum-signer/" + v + " (+https://github.com/ptudor/sigillum-dnssec/signer)"
}

// NewDynadotClient validates credentials and constructs a client. The adapter
// requires both api_key and api_secret in the config file; there is no env
// fallback because the config file (mode 0640) is the stricter surface than
// rc.d / systemd unit files.
func NewDynadotClient(cfg *config.RegistrarDynadotConfig) (*DynadotClient, error) {
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
	if override := strings.TrimSpace(cfg.BaseURL); override != "" {
		// The override is validated again here, not only at config load
		// (RDAYBLUEX-014): credentials never travel over cleartext to a
		// non-loopback host, whatever path built the config.
		if err := config.ValidateRegistrarBaseURL(cfg); err != nil {
			return nil, err
		}
		baseURL = strings.TrimRight(override, "/")
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
		// Redirects are never followed (RDAYBLUEX-014): the API has none, and
		// following one would replay the Authorization and X-Signature
		// headers — and a 307/308 body — to a target the path-bound
		// signature was never computed for, possibly over cleartext or to
		// another origin. A redirect surfaces as a dispatched error.
		http: &http.Client{Timeout: timeout, CheckRedirect: refuseRedirects},
		// Share ONE limiter across every DynadotClient in the process: RegistrarFor
		// builds a fresh client per call, so a per-client limiter would reset the
		// sliding window on each operation and never actually throttle a bulk push
		// across operations. One Dynadot account == one rate budget (R-073).
		limiter: sharedDynadotLimiter,
	}, nil
}

// refuseRedirects is the client's redirect policy: none are followed. The
// error names only the redacted target, never headers or credentials.
func refuseRedirects(req *http.Request, via []*http.Request) error {
	return fmt.Errorf("dynadot redirect refused (credentials are never replayed): %s -> %s", via[0].URL.Redacted(), req.URL.Redacted())
}

// maxDynadotResponseBytes caps a response body; a larger body is rejected,
// not parsed from its prefix (RDAYBLUEX-034).
const maxDynadotResponseBytes = 1 << 20

// readBodyLimited reads at most limit bytes and fails when the body is larger.
func readBodyLimited(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response body exceeds %d bytes", limit)
	}
	return data, nil
}

// Name returns the adapter identifier used in config.
func (c *DynadotClient) Name() string { return "dynadot" }

// sign computes the Base64-encoded HMAC-SHA256 signature for one request.
// `path` must be exactly the `fullPathAndQuery` the server sees (including
// query string when present) — any mismatch produces "X-Signature invalid"
// (HTTP 400 with Dynadot's specific error body) on the server side.
//
// Emits a debug log of the string being signed when DEBUG is enabled so
// operators can eyeball byte-for-byte what went into the HMAC. Neither the
// api key nor the secret is ever logged (CLAUDE.md contract): the key is
// redacted to a fixed placeholder in the logged string-to-sign, and only the
// resulting signature and the field lengths are surfaced.
func (c *DynadotClient) sign(path, requestID, body string) string {
	stringToSign := c.apiKey + "\n" + path + "\n" + requestID + "\n" + body
	mac := hmac.New(sha256.New, []byte(c.apiSecret))
	mac.Write([]byte(stringToSign))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Log the string-to-sign with the api key redacted so troubleshooting at
	// debug level never leaks the credential into logs that may be shipped or
	// retained. The remaining fields (path, request id, body) are what actually
	// vary between requests and are non-secret.
	redactedStringToSign := "<api_key>\n" + path + "\n" + requestID + "\n" + body
	slog.Debug("[REGISTRAR] dynadot signing",
		"api_key_len", len(c.apiKey),
		"api_secret_len", len(c.apiSecret),
		"string_to_sign_redacted", redactedStringToSign,
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
	// Dynadot puts the human-readable error text here on 4xx responses;
	// `message` is just the HTTP status text ("Bad Request"), not useful
	// to the operator. Example body:
	//   {"code":400,"message":"Bad Request","error":{"description":"This TLD isn't supported via the API."}}
	Error struct {
		Description string `json:"description"`
	} `json:"error,omitempty"`
}

// bestErrorMessage returns the most operator-useful string from an API
// response: Dynadot's error.description takes precedence over the generic
// message (which is just HTTP status text). Falls back to message and
// finally to stock http.StatusText upstream.
func (e *apiError) bestErrorMessage() string {
	if e.Error.Description != "" {
		return e.Error.Description
	}
	return e.Message
}

// do executes a signed request against the given relative path. `body` can
// be nil for GET/DELETE. The returned `data` is whatever was inside the
// envelope's `data` field on success; errors carry Dynadot's message
// verbatim so operators can see exact text like "The domain doesn't
// support DNSSEC." in logs.
func (c *DynadotClient) do(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	// Gate every outgoing request through the sliding-scale limiter so
	// bursts self-throttle before Dynadot's 60/min cap kicks in with a 429.
	// The limiter honors ctx, so a cancelled/expired caller isn't stuck behind
	// the throttle (R-073).
	if c.limiter != nil {
		if err := c.limiter.gate(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter wait cancelled: %w", err)
		}
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

	// From here on the request may have reached the registrar: every failure
	// is wrapped as dispatched so destructive callers treat it as an
	// uncertain outcome rather than a no-op (RA6X-031).
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &dispatchedError{fmt.Errorf("dynadot %s %s: %w", method, path, err)}
	}
	defer resp.Body.Close()

	raw, err := readBodyLimited(resp.Body, maxDynadotResponseBytes)
	if err != nil {
		// Still an uncertain (dispatched) outcome: the request reached the
		// registrar; only its answer could not be taken (RDAYBLUEX-034).
		return nil, &dispatchedError{fmt.Errorf("reading dynadot response: %w", err)}
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
		return nil, &dispatchedError{fmt.Errorf("dynadot %s %s (HTTP %d): non-JSON body: %q",
			method, path, resp.StatusCode, truncate(string(raw), 256))}
	}

	// The HTTP status code is authoritative; the envelope's `code` should
	// echo it. Accept any 2xx — set_dnssec / clear_dnssec can return 204
	// No Content on success, which earlier code mis-classified as an error.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := env.bestErrorMessage()
		if msg == "" {
			// Fall back to a truncated raw body so responses without any
			// structured error field still tell the operator what
			// Dynadot actually said.
			msg = truncate(strings.TrimSpace(string(raw)), 256)
			if msg == "" {
				msg = http.StatusText(resp.StatusCode)
			}
		}
		return nil, &dispatchedError{fmt.Errorf("dynadot %s %s: HTTP %d: %s", method, path, resp.StatusCode, msg)}
	}
	if env.Code != 0 && (env.Code < 200 || env.Code >= 300) {
		// Dynadot sometimes returns HTTP 200 with a failure code in the
		// envelope instead of a real 4xx. Surface error.description the
		// same way we do for real HTTP errors, and debug-log the raw
		// body so operators can triage without redeploying.
		slog.Debug("[REGISTRAR] dynadot envelope-code error response",
			"method", method, "path", path, "envelope_code", env.Code,
			"body", truncate(string(raw), 1024))
		msg := env.bestErrorMessage()
		if msg == "" {
			msg = truncate(strings.TrimSpace(string(raw)), 256)
		}
		return nil, &dispatchedError{fmt.Errorf("dynadot %s %s: envelope code %d: %s", method, path, env.Code, msg)}
	}

	return env.Data, nil
}

// dispatchedError wraps a failure from a request that may have reached the
// registrar and been applied (transport error, timeout, cancellation while in
// flight, unreadable or non-JSON response, error status). A destructive
// operation that fails this way has an uncertain outcome and must reconcile
// the registrar's actual state instead of assuming nothing changed.
type dispatchedError struct{ err error }

func (e *dispatchedError) Error() string { return e.err.Error() }
func (e *dispatchedError) Unwrap() error { return e.err }

// wasDispatched reports whether err came from a request that may have been
// applied by the registrar.
func wasDispatched(err error) bool {
	var d *dispatchedError
	return errors.As(err, &d)
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

// dynadotDSRecord matches a single entry in GET /dnssec. Dynadot's beta
// REST API has varied between snake_case/camelCase and string/number JSON
// values, so UnmarshalJSON accepts both documented and observed shapes.
type dynadotDSRecord struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  string `json:"algorithm"`
	DigestType string `json:"digest_type"`
	Digest     string `json:"digest"`
}

func (r *dynadotDSRecord) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	keyTag, err := dynadotRawUint16(raw, "key_tag", "keyTag")
	if err != nil {
		return err
	}
	algorithm, err := dynadotRawString(raw, "algorithm")
	if err != nil {
		return err
	}
	digestType, err := dynadotRawString(raw, "digest_type", "digestType")
	if err != nil {
		return err
	}
	digest, err := dynadotRawString(raw, "digest")
	if err != nil {
		return err
	}

	r.KeyTag = keyTag
	r.Algorithm = algorithm
	r.DigestType = digestType
	r.Digest = digest
	return nil
}

// dynadotGetDNSSECData is the `data` portion of a get_dnssec response.
// The list key accepts documented snake_case and observed camelCase forms.
type dynadotGetDNSSECData struct {
	DNSSECInfoList []dynadotDSRecord `json:"dnssec_info_list"`
}

func (d *dynadotGetDNSSECData) UnmarshalJSON(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}

	listRaw, ok := dynadotRawField(raw, "dnssec_info_list", "dnssecInfoList")
	if !ok {
		return fmt.Errorf("missing dnssec_info_list in dynadot data object")
	}
	if err := json.Unmarshal(listRaw, &d.DNSSECInfoList); err != nil {
		return fmt.Errorf("parsing dnssec_info_list: %w", err)
	}
	return nil
}

func dynadotRawField(raw map[string]json.RawMessage, names ...string) (json.RawMessage, bool) {
	for _, name := range names {
		if v, ok := raw[name]; ok {
			return v, true
		}
	}
	return nil, false
}

func dynadotRawString(raw map[string]json.RawMessage, names ...string) (string, error) {
	v, ok := dynadotRawField(raw, names...)
	if !ok {
		return "", fmt.Errorf("missing %s", names[0])
	}

	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return s, nil
	}

	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(v))
	dec.UseNumber()
	if err := dec.Decode(&n); err == nil {
		return n.String(), nil
	}

	return "", fmt.Errorf("%s must be a string or number", names[0])
}

func dynadotRawUint16(raw map[string]json.RawMessage, names ...string) (uint16, error) {
	s, err := dynadotRawString(raw, names...)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%s %q: not a uint16", names[0], s)
	}
	return uint16(n), nil
}

// dynadotSetDNSSECBody mirrors the docs' Request Body shape verbatim:
// snake_case field names, key_tag as Integer, everything else as String.
// All six fields are always serialized — earlier attempts that omitted
// flags and public_key produced "algorithm is missing" even with valid
// algorithm values, suggesting Dynadot's deserializer requires all
// declared fields present (the two "form discriminator" fields included)
// before it walks the record and finds algorithm.
type dynadotSetDNSSECBody struct {
	KeyTag     uint16 `json:"key_tag"`
	DigestType string `json:"digest_type"`
	Digest     string `json:"digest"`
	Algorithm  string `json:"algorithm"`
	Flags      string `json:"flags"`
	PublicKey  string `json:"public_key"`
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

// AddDS publishes DS records one at a time. Follows the docs' JSON body
// shape exactly — all six documented fields, snake_case names, key_tag
// as Integer, everything else as String. The DNSKEY-form fields (flags,
// public_key) are serialized as empty strings because we always publish
// in DS form; Dynadot appears to require the keys be present regardless.
func (c *DynadotClient) AddDS(ctx context.Context, domain string, records []*dns.DS) error {
	for _, ds := range records {
		body := dynadotSetDNSSECBody{
			KeyTag:     ds.KeyTag,
			DigestType: strconv.FormatUint(uint64(ds.DigestType), 10),
			Digest:     ds.Digest,
			Algorithm:  strconv.FormatUint(uint64(ds.Algorithm), 10),
			Flags:      "",
			PublicKey:  "",
		}
		if _, err := c.do(ctx, http.MethodPut, dnssecPath(domain), body); err != nil {
			return fmt.Errorf("set_dnssec (key_tag %d): %w", ds.KeyTag, err)
		}
		slog.Info("[REGISTRAR] dynadot DS published",
			"domain", domain, "key_tag", ds.KeyTag, "algorithm", ds.Algorithm, "digest_type", ds.DigestType)
	}
	return nil
}

// ReplaceDS leaves the registrar with exactly `records`. Sequence:
//  1. PUT each desired record (additive upsert by key_tag).
//  2. DELETE the entire DS set.
//  3. PUT each desired record again, then GET the set and verify it.
//
// PUT-first is deliberate: if the PUT format is wrong, the credentials are
// wrong, or the API is down, step 1 fails and we return *before any
// destructive op*, leaving whatever the registrar previously held intact.
//
// The DELETE is an uncertain destructive operation (RA6X-031): a transport
// error, a timeout, a cancellation while in flight or an unreadable response
// may all hide a deletion the server applied. Any such failure is treated as
// "possibly cleared": the restore and its verification run regardless, on a
// context detached from the caller with a fresh bounded budget and recovery
// priority at the rate limiter, and the postcondition is established by
// reading the set back — never by assuming an accepted response means the set
// is correct. When the desired records cannot be verified present, the error
// unwraps to ErrRegistrarDSEmpty so callers escalate and persist remediation
// state. Extra records that survive a DELETE that did not apply are reported
// as an ordinary error: no DS is ever deleted merely to resolve uncertainty.
//
// Passing an empty `records` slice is `registrar clear`: only the DELETE is
// issued; an uncertain outcome is reconciled by reading the set back.
func (c *DynadotClient) ReplaceDS(ctx context.Context, domain string, records []*dns.DS) error {
	if len(records) > 0 {
		if err := c.AddDS(ctx, domain, records); err != nil {
			return fmt.Errorf("publish before clear: %w", err)
		}
	}

	_, delErr := c.do(ctx, http.MethodDelete, dnssecPath(domain), nil)
	if delErr != nil && !wasDispatched(delErr) {
		// Never reached the registrar; nothing was cleared. The desired
		// records were already published additively above.
		return fmt.Errorf("clear_dnssec (not sent): %w", delErr)
	}
	if delErr == nil {
		slog.Info("[REGISTRAR] dynadot DS cleared", "domain", domain)
	} else {
		slog.Warn("[REGISTRAR] dynadot DS clear outcome uncertain; reconciling the registrar's actual DS set",
			"domain", domain, "error", delErr)
	}

	// Recovery runs detached from the caller's context (a cancel or an
	// almost-spent parent deadline must not abort it), with a fresh budget and
	// priority at the rate limiter.
	recoveryCtx, cancel := context.WithTimeout(withRecoveryPriority(context.WithoutCancel(ctx)), 2*time.Minute)
	defer cancel()

	if len(records) == 0 {
		if delErr == nil {
			return nil
		}
		have, err := c.GetDS(recoveryCtx, domain)
		if err != nil {
			return fmt.Errorf("clear_dnssec: outcome uncertain (%v) and the DS set could not be read back: %w", delErr, err)
		}
		if len(have) == 0 {
			slog.Info("[REGISTRAR] dynadot DS clear confirmed by read-back", "domain", domain)
			return nil
		}
		return fmt.Errorf("clear_dnssec: %w (the registrar still holds %d DS record(s))", delErr, len(have))
	}

	const restoreAttempts = 3
	lastErr := delErr
	for attempt := 1; attempt <= restoreAttempts; attempt++ {
		if err := c.AddDS(recoveryCtx, domain, records); err != nil {
			lastErr = err
			slog.Warn("[REGISTRAR] dynadot DS restore attempt failed",
				"domain", domain, "attempt", attempt, "max_attempts", restoreAttempts, "error", err)
		} else if have, err := c.GetDS(recoveryCtx, domain); err != nil {
			lastErr = fmt.Errorf("verifying the DS set after restore: %w", err)
			slog.Warn("[REGISTRAR] dynadot DS set could not be read back after restore",
				"domain", domain, "attempt", attempt, "error", err)
		} else {
			missing, extra := CompareDSSets(records, have)
			if len(missing) == 0 {
				if len(extra) > 0 {
					return fmt.Errorf("registrar holds the desired DS set but %d extra DS record(s) remain because the clear did not apply (%v); re-run `sigillum-signer registrar push %s`",
						len(extra), delErr, domain)
				}
				slog.Info("[REGISTRAR] dynadot DS set verified", "domain", domain, "records", len(records))
				return nil
			}
			lastErr = fmt.Errorf("%d of %d desired DS record(s) not present after restore", len(missing), len(records))
			slog.Warn("[REGISTRAR] dynadot DS restore not yet visible", "domain", domain, "attempt", attempt, "missing", len(missing))
		}
		if attempt < restoreAttempts {
			if err := sleepCtx(recoveryCtx, time.Duration(attempt)*time.Second); err != nil {
				break // budget exhausted; surface the sentinel
			}
		}
	}
	return fmt.Errorf("%w: zone %s DS set could not be verified after %d restore attempts: %v",
		ErrRegistrarDSEmpty, domain, restoreAttempts, lastErr)
}

// parseDynadotUint8 parses Dynadot's algorithm / digest_type field into the
// uint8 the DNS library expects. The live API returns labeled values like
// "ED25519 (15)" or "SHA-256 (2)" rather than the bare numeric strings the
// docs implied, so this accepts both shapes:
//
//	"15"           → 15
//	"ED25519 (15)" → 15
//	"  2 "         → 2
//	"SHA-256 (2)"  → 2
//
// Strategy: try a bare numeric parse first; on failure, extract the integer
// inside the last "(...)" group. Order matters — bare-numeric is the
// documented contract, and we want a regression there to surface clearly
// instead of silently being rescued by paren-extraction.
func parseDynadotUint8(s, field string) (uint8, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("dynadot %s missing", field)
	}
	if n, err := strconv.ParseUint(s, 10, 8); err == nil {
		return uint8(n), nil
	}
	if open := strings.LastIndex(s, "("); open >= 0 {
		if close := strings.Index(s[open:], ")"); close > 0 {
			inner := strings.TrimSpace(s[open+1 : open+close])
			if n, err := strconv.ParseUint(inner, 10, 8); err == nil {
				return uint8(n), nil
			}
		}
	}
	return 0, fmt.Errorf("dynadot %s %q: not a uint8 (expected bare integer or \"name (N)\" form)", field, s)
}
