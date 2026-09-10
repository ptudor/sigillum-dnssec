package dns

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// RDAYBLUEX-034: HTTP body limits reject, rather than truncate, a response
// larger than the advertised maximum.

func TestRDAYBLUEX034_ReadBodyLimited(t *testing.T) {
	data, err := ReadBodyLimited(strings.NewReader("12345"), 5, "x")
	if err != nil || string(data) != "12345" {
		t.Fatalf("exactly-at-limit must be read whole: %q %v", data, err)
	}
	data, err = ReadBodyLimited(strings.NewReader("1234"), 5, "x")
	if err != nil || string(data) != "1234" {
		t.Fatalf("below the limit must be read whole: %q %v", data, err)
	}
	if _, err := ReadBodyLimited(strings.NewReader("123456"), 5, "x"); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("one byte over the limit must be rejected, got %v", err)
	}
	if _, err := ReadBodyLimited(strings.NewReader("1"), 0, "x"); err == nil {
		t.Fatal("a non-positive limit is invalid")
	}
}

// The anchor loader: a valid document padded to end exactly at the limit
// followed by one more byte is refused as oversized, not parsed from its
// prefix; an at-limit document reaches the parser.
func TestRDAYBLUEX034_AnchorLoaderRejectsOversizedBody(t *testing.T) {
	limit := 1 << 20
	pad := func(total int, extra string) string {
		head := `{"source":"`
		tail := `","zone":".","anchors":[]}`
		return head + strings.Repeat("x", total-len(head)-len(tail)) + tail + extra
	}
	serve := func(body string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return srv
	}
	_, err := LoadAnchorsFromURL(serve(pad(limit, "\n")).URL)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("an oversized anchor document must be rejected as such, got %v", err)
	}
	_, err = LoadAnchorsFromURL(serve(pad(limit, "")).URL)
	if errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("an at-limit document must reach the parser (its content may still be rejected), got %v", err)
	}
	_, err = LoadAnchorsFromURL(serve(strings.Repeat("z", limit+1)).URL)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("large non-JSON must be rejected as oversized, got %v", err)
	}
}
