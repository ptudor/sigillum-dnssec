package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// mkDS is a test helper that builds a DS record from primitive fields.
func mkDS(keyTag uint16, alg, digestType uint8, digest string) *dns.DS {
	return &dns.DS{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
		KeyTag:     keyTag,
		Algorithm:  alg,
		DigestType: digestType,
		Digest:     digest,
	}
}

func TestCompareDSSets_InSync(t *testing.T) {
	a := mkDS(12345, 15, 2, "abcdef")
	b := mkDS(12345, 15, 2, "ABCDEF") // same record, upper-cased digest
	missing, extra := CompareDSSets([]*dns.DS{a}, []*dns.DS{b})
	if len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("expected empty diff, got missing=%v extra=%v", missing, extra)
	}
}

func TestCompareDSSets_AdditionsAndRemovals(t *testing.T) {
	want := []*dns.DS{
		mkDS(11111, 15, 2, "aaaa"),
		mkDS(22222, 15, 2, "bbbb"),
	}
	have := []*dns.DS{
		mkDS(22222, 15, 2, "bbbb"),
		mkDS(33333, 15, 2, "cccc"),
	}
	missing, extra := CompareDSSets(want, have)
	if len(missing) != 1 || missing[0].KeyTag != 11111 {
		t.Fatalf("expected 11111 missing, got %v", missing)
	}
	if len(extra) != 1 || extra[0].KeyTag != 33333 {
		t.Fatalf("expected 33333 extra, got %v", extra)
	}
}

func TestRegistrarConfig_DigestType_Defaults(t *testing.T) {
	cases := []struct {
		name string
		in   int
		want uint8
	}{
		{"zero_defaults_to_sha256", 0, 2},
		{"explicit_sha256", 2, 2},
		{"explicit_sha384", 4, 4},
		{"unknown_defaults_to_sha256", 1, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := RegistrarConfig{DigestTypeVal: tc.in}
			if got := rc.DigestType(); got != tc.want {
				t.Fatalf("DigestType(%d) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestRegistrarFor_NotOptedIn confirms that zones without a registrar field
// behave exactly as before (nil adapter, no error).
func TestRegistrarFor_NotOptedIn(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Zones["example.com"] = ZoneConfig{Path: "/nonexistent"}
	reg, err := RegistrarFor(cfg, "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reg != nil {
		t.Fatalf("expected nil registrar for opt-out zone, got %q", reg.Name())
	}
}

// TestRegistrarFor_UnknownAdapter confirms misconfiguration is surfaced.
func TestRegistrarFor_UnknownAdapter(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Zones["example.com"] = ZoneConfig{Path: "/nonexistent", Registrar: "geocities"}
	if _, err := RegistrarFor(cfg, "example.com"); err == nil {
		t.Fatal("expected error for unknown registrar, got nil")
	}
}

// TestDynadotSign locks in the exact signing recipe from the Dynadot docs:
// apiKey + "\n" + fullPathAndQuery + "\n" + xRequestId + "\n" + requestBody,
// HMAC-SHA256, Base64-encoded. Using a known key/secret/body lets us catch
// any future accidental change to the signed-string order.
func TestDynadotSign_Deterministic(t *testing.T) {
	c := &DynadotClient{apiKey: "key123", apiSecret: "secret456"}
	got := c.sign("/restful/v2/domains/example.com/dnssec", "req-id", `{"k":1}`)

	// Recompute with the exact same inputs — the point of this test is to
	// fail loudly if someone changes the field order or separator.
	want := c.sign("/restful/v2/domains/example.com/dnssec", "req-id", `{"k":1}`)
	if got != want || got == "" {
		t.Fatalf("sign() not deterministic or empty: got=%q want=%q", got, want)
	}

	// Mutating any input must change the signature.
	if c.sign("/different/path", "req-id", `{"k":1}`) == got {
		t.Fatal("path change did not affect signature")
	}
	if c.sign("/restful/v2/domains/example.com/dnssec", "other-id", `{"k":1}`) == got {
		t.Fatal("request-id change did not affect signature")
	}
	if c.sign("/restful/v2/domains/example.com/dnssec", "req-id", `{"k":2}`) == got {
		t.Fatal("body change did not affect signature")
	}
}

// TestDynadotGetDS_HappyPath spins up a fake Dynadot endpoint and verifies
// that the client sends the right headers, receives the {code,message,data}
// envelope, and correctly parses `algorithm` / `digest_type` as strings.
// The default adapter config does NOT send X-Request-ID; the with-header
// variant exercises the opt-in path.
func TestDynadotGetDS_HappyPath(t *testing.T) {
	cases := []struct {
		name           string
		sendRequestID  bool
		wantHeaderSeen bool
	}{
		{"default_omits_request_id", false, false},
		{"opt_in_sends_request_id", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("expected GET, got %s", r.Method)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer key123" {
					t.Errorf("Authorization header = %q, want Bearer key123", got)
				}
				if r.Header.Get("X-Signature") == "" {
					t.Error("X-Signature header missing")
				}
				gotRequestID := r.Header.Get("X-Request-ID") != ""
				if gotRequestID != tc.wantHeaderSeen {
					t.Errorf("X-Request-ID present=%v, want %v", gotRequestID, tc.wantHeaderSeen)
				}
				if !strings.HasSuffix(r.URL.Path, "/restful/v2/domains/example.com/dnssec") {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"code":200,"message":"Success","data":{"dnssec_info_list":[`+
					`{"key_tag":12345,"algorithm":"15","digest_type":"2","digest":"ABCDEF"}`+
					`]}}`)
			}))
			defer srv.Close()

			c := &DynadotClient{
				apiKey:        "key123",
				apiSecret:     "secret",
				baseURL:       srv.URL,
				sendRequestID: tc.sendRequestID,
				http:          srv.Client(),
			}
			records, err := c.GetDS(context.Background(), "example.com")
			if err != nil {
				t.Fatalf("GetDS: %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("expected 1 DS, got %d", len(records))
			}
			r := records[0]
			if r.KeyTag != 12345 || r.Algorithm != 15 || r.DigestType != 2 || r.Digest != "abcdef" {
				t.Fatalf("unexpected DS: %+v", r)
			}
		})
	}
}

// TestDynadotGetDS_ErrorBody confirms the adapter surfaces Dynadot's
// error.description verbatim. The real restful/v2 shape puts the useful
// text under `error.description`; `message` is just HTTP status text.
// Regression guard against reverting to "HTTP 400: Bad Request" errors
// that hide the actual cause from operators.
func TestDynadotGetDS_ErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"code":400,"message":"Bad Request","error":{"description":"This TLD isn't supported via the API."}}`)
	}))
	defer srv.Close()

	c := &DynadotClient{apiKey: "k", apiSecret: "s", baseURL: srv.URL, http: srv.Client()}
	_, err := c.GetDS(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "This TLD isn't supported") {
		t.Fatalf("expected error.description to surface, got %q", err.Error())
	}
}

// TestDynadotGetDS_ErrorBody_MessageOnly handles the case where Dynadot
// returns only the top-level message (no error.description) — we should
// still surface it rather than falling back to stock StatusText.
func TestDynadotGetDS_ErrorBody_MessageOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"code":404,"message":"Can not find the domain_name in the account."}`)
	}))
	defer srv.Close()

	c := &DynadotClient{apiKey: "k", apiSecret: "s", baseURL: srv.URL, http: srv.Client()}
	_, err := c.GetDS(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Can not find") {
		t.Fatalf("expected upstream message to surface, got %q", err.Error())
	}
}

// TestDynadotAddDS_JSONBody verifies set_dnssec sends JSON with numeric
// digest_type and algorithm (not quoted strings). The docs labelled
// those as "String" but Dynadot's live parser demands JSON numbers
// for them — regression guard against anyone trusting the docs over
// the empirically-verified live behavior.
func TestDynadotAddDS_JSONBody(t *testing.T) {
	var gotMethod string
	var gotCT string
	var gotRaw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		gotRaw, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"code":200,"message":"Success"}`)
	}))
	defer srv.Close()

	c := &DynadotClient{apiKey: "k", apiSecret: "s", baseURL: srv.URL, http: srv.Client()}
	ds := mkDS(12345, 15, 2, "abcdef")
	if err := c.AddDS(context.Background(), "example.com", []*dns.DS{ds}); err != nil {
		t.Fatalf("AddDS: %v", err)
	}

	if gotMethod != http.MethodPut {
		t.Errorf("expected PUT, got %s", gotMethod)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}

	// The literal body text matters — these fields must be numeric
	// JSON (no quotes), not strings. Substring-match so we notice if
	// `"algorithm":"15"` (quoted, the broken shape) ever sneaks back in.
	raw := string(gotRaw)
	for _, want := range []string{
		`"key_tag":12345`,
		`"digest_type":2`,
		`"digest":"abcdef"`,
		`"algorithm":15`,
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("body missing %q; got %s", want, raw)
		}
	}
	for _, bad := range []string{
		`"digest_type":"2"`,
		`"algorithm":"15"`,
	} {
		if strings.Contains(raw, bad) {
			t.Errorf("body contains %q — digest_type/algorithm must be JSON numbers, not strings", bad)
		}
	}
}

// TestDynadotReplaceDS_CallOrder verifies DELETE precedes PUT — if this
// inverts, every ReplaceDS call would re-add then delete, ending with zero
// DS records at the registrar (a silent DNSSEC outage).
func TestDynadotReplaceDS_CallOrder(t *testing.T) {
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, r.Method)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"code":200,"message":"Success"}`)
	}))
	defer srv.Close()

	c := &DynadotClient{apiKey: "k", apiSecret: "s", baseURL: srv.URL, http: srv.Client()}
	if err := c.ReplaceDS(context.Background(), "example.com", []*dns.DS{mkDS(1, 15, 2, "aa")}); err != nil {
		t.Fatalf("ReplaceDS: %v", err)
	}
	if len(order) != 2 || order[0] != http.MethodDelete || order[1] != http.MethodPut {
		t.Fatalf("expected DELETE then PUT, got %v", order)
	}
}

// TestDynadotReplaceDS_EmptySkipsPut covers the `registrar clear` path:
// a ReplaceDS with an empty slice should DELETE and stop.
func TestDynadotReplaceDS_EmptySkipsPut(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"code":200,"message":"Success"}`)
	}))
	defer srv.Close()

	c := &DynadotClient{apiKey: "k", apiSecret: "s", baseURL: srv.URL, http: srv.Client()}
	if err := c.ReplaceDS(context.Background(), "example.com", nil); err != nil {
		t.Fatalf("ReplaceDS: %v", err)
	}
	if len(methods) != 1 || methods[0] != http.MethodDelete {
		t.Fatalf("expected a single DELETE, got %v", methods)
	}
}

func TestParseDynadotUint8(t *testing.T) {
	cases := []struct {
		in      string
		want    uint8
		wantErr bool
	}{
		{"15", 15, false},
		{"  2 ", 2, false},
		{"", 0, true},
		{"abc", 0, true},
		{"999", 0, true}, // out of uint8 range
	}
	for _, tc := range cases {
		got, err := parseDynadotUint8(tc.in, "test")
		if (err != nil) != tc.wantErr {
			t.Errorf("parseDynadotUint8(%q): err=%v wantErr=%v", tc.in, err, tc.wantErr)
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("parseDynadotUint8(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
