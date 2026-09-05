package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ptudor/dnssec-tudor/internal/config"
)

// recorder counts requests and remembers whether any body carried the marker.
type recorder struct {
	mu       sync.Mutex
	requests int
	sawKey   bool
}

func (r *recorder) handler(marker string, status int, location string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.requests++
		if strings.Contains(string(body), marker) {
			r.sawKey = true
		}
		r.mu.Unlock()
		if location != "" {
			w.Header().Set("Location", location)
			w.WriteHeader(status)
			return
		}
		w.WriteHeader(http.StatusOK)
	}
}

func (r *recorder) snapshot() (int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests, r.sawKey
}

const heartbeatMarker = "SYNTHETIC-HEARTBEAT-KEY-4d2f"

func TestHeartbeat_RedirectsNeverReplayTheKeyOffOrigin(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			otherTLS := &recorder{}
			otherSrv := httptest.NewTLSServer(otherTLS.handler(heartbeatMarker, 0, ""))
			defer otherSrv.Close()
			plain := &recorder{}
			plainSrv := httptest.NewServer(plain.handler(heartbeatMarker, 0, ""))
			defer plainSrv.Close()

			for _, target := range []struct {
				name string
				url  string
				rec  *recorder
			}{{"another HTTPS origin", otherSrv.URL, otherTLS}, {"cleartext HTTP", plainSrv.URL, plain}} {
				t.Run(target.name, func(t *testing.T) {
					origin := &recorder{}
					srv := httptest.NewTLSServer(origin.handler(heartbeatMarker, status, target.url))
					defer srv.Close()
					c := NewHeartbeatClient(&config.HeartbeatConfig{Enabled: true, URL: srv.URL, APIKey: heartbeatMarker, App: "test", IntervalMinutes: 60})
					c.httpClient.Transport = srv.Client().Transport // trust the test CA only; keep the redirect policy
					if err := c.Send("test"); err == nil {
						t.Fatal("a redirect off the configured origin must be an error")
					}
					if n, saw := target.rec.snapshot(); n != 0 || saw {
						t.Fatalf("the redirect target must receive no request (got %d, key seen %v)", n, saw)
					}
				})
			}
		})
	}
}

func TestHeartbeat_SameOriginRedirectAndLoopAndOverride(t *testing.T) {
	t.Run("same-origin redirect is followed", func(t *testing.T) {
		rec := &recorder{}
		mux := http.NewServeMux()
		mux.HandleFunc("/hb", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/hb/v2", http.StatusPermanentRedirect)
		})
		mux.HandleFunc("/hb/v2", rec.handler(heartbeatMarker, 0, ""))
		srv := httptest.NewTLSServer(mux)
		defer srv.Close()
		c := NewHeartbeatClient(&config.HeartbeatConfig{Enabled: true, URL: srv.URL + "/hb", APIKey: heartbeatMarker, App: "test", IntervalMinutes: 60})
		c.httpClient.Transport = srv.Client().Transport
		if err := c.Send("test"); err != nil {
			t.Fatalf("same-origin redirect must be followed: %v", err)
		}
		if n, saw := rec.snapshot(); n != 1 || !saw {
			t.Fatalf("the same-origin target must receive the heartbeat once (got %d, key %v)", n, saw)
		}
	})
	t.Run("redirect loop is bounded", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, r.URL.Path, http.StatusTemporaryRedirect)
		}))
		defer srv.Close()
		c := NewHeartbeatClient(&config.HeartbeatConfig{Enabled: true, URL: srv.URL + "/loop", APIKey: heartbeatMarker, App: "test", IntervalMinutes: 60})
		c.httpClient.Transport = srv.Client().Transport
		if err := c.Send("test"); err == nil {
			t.Fatal("a redirect loop must fail rather than spin")
		}
	})
	t.Run("allow_insecure permits an initial http URL but no cross-origin replay", func(t *testing.T) {
		other := &recorder{}
		otherSrv := httptest.NewServer(other.handler(heartbeatMarker, 0, ""))
		defer otherSrv.Close()
		origin := &recorder{}
		srv := httptest.NewServer(origin.handler(heartbeatMarker, http.StatusTemporaryRedirect, otherSrv.URL))
		defer srv.Close()
		c := NewHeartbeatClient(&config.HeartbeatConfig{Enabled: true, URL: srv.URL, APIKey: heartbeatMarker, App: "test", IntervalMinutes: 60, AllowInsecure: true})
		if err := c.Send("test"); err == nil {
			t.Fatal("cross-origin redirect must be refused even under allow_insecure")
		}
		if n, _ := origin.snapshot(); n != 1 {
			t.Fatalf("the configured http origin itself must have been contacted once, got %d", n)
		}
		if n, _ := other.snapshot(); n != 0 {
			t.Fatalf("the redirect target must receive nothing, got %d", n)
		}
	})
}
