package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ptudor/dnssec-tudor/internal/config"
)

// TestHeartbeat_EventSendsAreAsync (R-044): per-event heartbeats must not block
// the caller (the signing loop) even when the endpoint is blackholed.
func TestHeartbeat_EventSendsAreAsync(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // hang, simulating a blackholed endpoint
	}))
	defer srv.Close()
	defer close(block)

	c := NewHeartbeatClient(&config.HeartbeatConfig{Enabled: true, URL: srv.URL, App: "test", IntervalMinutes: 60})

	// Enqueue many events without a running worker: enqueue is non-blocking and
	// drops the oldest on backpressure, so this returns essentially instantly
	// even though the endpoint would block for 10s per send.
	start := time.Now()
	for i := 0; i < 200; i++ {
		c.SigningStart("example.com")
		c.SigningComplete("example.com", uint32(i))
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("async per-event sends must not block on a hung endpoint; took %v", elapsed)
	}
}

// TestHeartbeat_EventDelivered (R-044): an enqueued per-event heartbeat is
// actually delivered by the background worker.
func TestHeartbeat_EventDelivered(t *testing.T) {
	got := make(chan string, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got <- r.FormValue("action")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewHeartbeatClient(&config.HeartbeatConfig{Enabled: true, URL: srv.URL, App: "test", IntervalMinutes: 60})
	c.Start() // sends "starting" synchronously and starts the workers
	defer c.Stop()

	c.SigningComplete("example.com", 42)

	deadline := time.After(3 * time.Second)
	for {
		select {
		case a := <-got:
			if strings.HasPrefix(a, "signing:complete domain=example.com") {
				return // delivered
			}
		case <-deadline:
			t.Fatal("did not receive the async signing:complete heartbeat")
		}
	}
}
