package main

import (
	"net/http/httptest"
	"testing"
	"time"
)

// deadlineRecorder is a ResponseWriter that supports SetWriteDeadline (like a real
// TCP connection) so http.ResponseController can arm it, and records the deadline.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
	set      bool
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadline = t
	d.set = true
	return nil
}

// R-046: each SSE event arms a fresh per-event write deadline so a stuck client
// cannot block the validation goroutine (and its held semaphore slot) forever.
func TestR046_SSEArmsPerEventDeadline(t *testing.T) {
	dr := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	s, err := NewSSEWriter(dr)
	if err != nil {
		t.Fatalf("NewSSEWriter: %v", err)
	}

	if err := s.WriteEvent("zone", map[string]string{"zone": "."}); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	if !dr.set {
		t.Fatal("WriteEvent must arm a per-event write deadline")
	}
	if until := time.Until(dr.deadline); until <= 0 || until > 2*defaultSSEEventWriteTimeout {
		t.Fatalf("deadline not armed ~writeTimeout in the future: %v", until)
	}

	// A subsequent event re-arms (slides) the deadline.
	dr.set = false
	if err := s.WriteComment("keep-alive"); err != nil {
		t.Fatalf("WriteComment: %v", err)
	}
	if !dr.set {
		t.Fatal("each event/keep-alive must re-arm the sliding deadline")
	}
}
