package registrar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// --- RA6X-051: rolling-window quota and cancellation ------------------------

// fakeClock drives a windowLimiter deterministically: wait advances the clock
// instead of sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return nil
}

func clockedLimiter() (*windowLimiter, *fakeClock) {
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	l := newWindowLimiter()
	l.now = clk.Now
	l.wait = clk.Wait
	return l, clk
}

// maxInAnyWindow returns the largest number of admissions inside any rolling
// window of the given length.
func maxInAnyWindow(times []time.Time, window time.Duration) int {
	best := 0
	for i := range times {
		n := 0
		for j := i; j < len(times) && times[j].Sub(times[i]) < window; j++ {
			n++
		}
		if n > best {
			best = n
		}
	}
	return best
}

func TestWindowLimiter_RollingQuota(t *testing.T) {
	l, clk := clockedLimiter()
	var admissions []time.Time
	for i := 0; i < 400; i++ {
		if err := l.gate(context.Background()); err != nil {
			t.Fatal(err)
		}
		admissions = append(admissions, clk.Now())
	}
	if got := maxInAnyWindow(admissions, time.Minute); got > dynadotQuota-dynadotRecoveryReserve {
		t.Fatalf("ordinary callers admitted %d in a rolling minute, budget is %d", got, dynadotQuota-dynadotRecoveryReserve)
	}
	// The burst tiers still shape the front of a burst.
	for i := 1; i < 20; i++ {
		if gap := admissions[i].Sub(admissions[i-1]); gap < 100*time.Millisecond {
			t.Fatalf("admission %d followed the previous by %v, want the 100ms tier gap", i, gap)
		}
	}
	if gap := admissions[25].Sub(admissions[24]); gap < 500*time.Millisecond {
		t.Fatalf("admission 25 gap %v, want the 500ms tier", gap)
	}
}

// Idle resets, concurrent clients on the shared limiter, and retries never
// exceed the quota; recovery-priority callers may use the reserve but never
// exceed the full quota.
func TestWindowLimiter_QuotaAcrossIdleAndPriority(t *testing.T) {
	l, clk := clockedLimiter()
	var all, priority []time.Time
	for round := 0; round < 3; round++ {
		for i := 0; i < 70; i++ {
			if err := l.gate(context.Background()); err != nil {
				t.Fatal(err)
			}
			all = append(all, clk.Now())
		}
		clk.Wait(context.Background(), 90*time.Second) // idle → window empties
	}
	// Exhaust the ordinary budget, then recovery work must still be admitted.
	for i := 0; i < dynadotQuota-dynadotRecoveryReserve; i++ {
		if err := l.gate(context.Background()); err != nil {
			t.Fatal(err)
		}
		all = append(all, clk.Now())
	}
	before := clk.Now()
	for i := 0; i < dynadotRecoveryReserve; i++ {
		if err := l.gate(withRecoveryPriority(context.Background())); err != nil {
			t.Fatal(err)
		}
		priority = append(priority, clk.Now())
		all = append(all, clk.Now())
	}
	if priority[len(priority)-1].Sub(before) > 30*time.Second {
		t.Fatalf("recovery calls waited %v behind an exhausted ordinary budget; the reserve must admit them", priority[len(priority)-1].Sub(before))
	}
	if got := maxInAnyWindow(all, time.Minute); got > dynadotQuota {
		t.Fatalf("%d admissions in a rolling minute exceeds the quota %d", got, dynadotQuota)
	}
}

func TestWindowLimiter_Cancellation(t *testing.T) {
	t.Run("already cancelled with no delay due", func(t *testing.T) {
		l := newWindowLimiter()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := l.gate(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
		if l.admissionsInWindow() != 0 {
			t.Fatal("a cancelled caller must not consume a slot")
		}
	})
	t.Run("queued behind a long wait returns promptly", func(t *testing.T) {
		l := newWindowLimiter()
		// 45 admissions in the window → next ordinary caller waits the 2s tier.
		now := time.Now()
		for i := 0; i < 45; i++ {
			l.admitted = append(l.admitted, now.Add(-time.Duration(45-i)*100*time.Millisecond))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		start := time.Now()
		err := l.gate(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v, want deadline exceeded", err)
		}
		if time.Since(start) > 200*time.Millisecond {
			t.Fatalf("cancellation observed after %v; it must not wait behind the throttle", time.Since(start))
		}
		if l.admissionsInWindow() != 45 {
			t.Fatal("a cancelled caller must not consume a slot")
		}
	})
	t.Run("queued behind another waiter observes its own deadline", func(t *testing.T) {
		l := newWindowLimiter()
		if err := l.gate(context.Background()); err != nil {
			t.Fatal(err)
		}
		// One caller sits in its wait; a second with a short deadline must
		// not be blocked behind it.
		go func() { _ = l.gate(context.Background()) }()
		time.Sleep(5 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		start := time.Now()
		if err := l.gate(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %v, want deadline exceeded", err)
		}
		if time.Since(start) > 60*time.Millisecond {
			t.Fatalf("second caller waited %v behind the first", time.Since(start))
		}
	})
}

// --- RA6X-031: uncertain DELETE outcomes -----------------------------------

// dsStore is a simulated registrar DS set with configurable DELETE behaviour.
type dsStore struct {
	mu       sync.Mutex
	records  map[string]bool
	pending  map[string]int // records that become visible after N GETs (async acceptance)
	puts     int
	deletes  int
	gets     int
	requests int
	// behaviours
	onDelete func(w http.ResponseWriter, s *dsStore) // nil = normal
	putFails func(n int) bool
	getFails func(n int) bool
}

func newDSStore(initial ...string) *dsStore {
	s := &dsStore{records: map[string]bool{}, pending: map[string]int{}}
	for _, r := range initial {
		s.records[r] = true
	}
	return s
}

func (s *dsStore) serve(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.requests++
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPut:
			s.puts++
			if s.putFails != nil && s.putFails(s.puts) {
				w.WriteHeader(http.StatusInternalServerError)
				io.WriteString(w, `{"code":500,"message":"down"}`)
				return
			}
			body, _ := io.ReadAll(r.Body)
			var b struct {
				KeyTag uint16 `json:"key_tag"`
			}
			_ = jsonUnmarshal(body, &b)
			key := fmt.Sprintf("%d", b.KeyTag)
			if n, ok := s.pending[key]; ok && n > 0 {
				// asynchronous acceptance: visible after n GETs
			} else {
				s.records[key] = true
			}
			io.WriteString(w, `{"code":200,"message":"Success"}`)
		case http.MethodDelete:
			s.deletes++
			if s.onDelete != nil {
				s.onDelete(w, s)
				return
			}
			s.records = map[string]bool{}
			io.WriteString(w, `{"code":200,"message":"Success"}`)
		case http.MethodGet:
			s.gets++
			if s.getFails != nil && s.getFails(s.gets) {
				w.WriteHeader(http.StatusBadGateway)
				io.WriteString(w, `{"code":502,"message":"upstream"}`)
				return
			}
			for key, n := range s.pending {
				if n <= 1 {
					s.records[key] = true
					delete(s.pending, key)
				} else {
					s.pending[key] = n - 1
				}
			}
			var items []string
			for key := range s.records {
				items = append(items, fmt.Sprintf(`{"key_tag":%s,"algorithm":"15","digest_type":"2","digest":"aa"}`, key))
			}
			io.WriteString(w, `{"code":200,"message":"Success","data":{"dnssec_info_list":[`+strings.Join(items, ",")+`]}}`)
		}
	}))
}

func (s *dsStore) has(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records[key]
}

func (s *dsStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func clientFor(srv *httptest.Server, timeout time.Duration) *DynadotClient {
	c := &DynadotClient{apiKey: "k", apiSecret: "s", baseURL: srv.URL, http: srv.Client()}
	c.http.Timeout = timeout
	return c
}

// applyThenDrop applies the DELETE and then drops the connection without a response.
func applyThenDrop(w http.ResponseWriter, s *dsStore) {
	s.records = map[string]bool{}
	panic(http.ErrAbortHandler)
}

func TestReplaceDS_UncertainDeleteIsReconciled(t *testing.T) {
	desired := []*dns.DS{mkDS(1, 15, 2, "aa")}
	cases := []struct {
		name     string
		onDelete func(w http.ResponseWriter, s *dsStore)
		timeout  time.Duration
	}{
		{"applied then connection dropped", applyThenDrop, 5 * time.Second},
		{"applied then response timed out", func(w http.ResponseWriter, s *dsStore) {
			s.records = map[string]bool{}
			s.mu.Unlock()
			time.Sleep(400 * time.Millisecond)
			s.mu.Lock()
			io.WriteString(w, `{"code":200,"message":"Success"}`)
		}, 150 * time.Millisecond},
		{"applied then non-JSON response", func(w http.ResponseWriter, s *dsStore) {
			s.records = map[string]bool{}
			io.WriteString(w, `<html>gateway</html>`)
		}, 5 * time.Second},
		{"applied then HTTP 500", func(w http.ResponseWriter, s *dsStore) {
			s.records = map[string]bool{}
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"code":500,"message":"oops"}`)
		}, 5 * time.Second},
		{"not applied, connection dropped", func(w http.ResponseWriter, s *dsStore) {
			panic(http.ErrAbortHandler)
		}, 5 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := newDSStore("9") // an old DS that ReplaceDS must remove
			store.onDelete = tc.onDelete
			srv := store.serve(t)
			defer srv.Close()
			c := clientFor(srv, tc.timeout)
			err := c.ReplaceDS(context.Background(), "example.com", desired)
			if !store.has("1") {
				t.Fatalf("desired DS must be present after an uncertain clear (err %v)", err)
			}
			if store.has("9") {
				// The clear did not apply: the safe state is reported, never fixed by another DELETE.
				if err == nil || errors.Is(err, ErrRegistrarDSEmpty) || !strings.Contains(err.Error(), "extra") {
					t.Fatalf("surviving old DS must be reported as an ordinary error, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("restore after an uncertain clear must succeed, got %v", err)
			}
		})
	}
}

func TestReplaceDS_CallerCancelledDuringDelete(t *testing.T) {
	store := newDSStore("9")
	ctx, cancel := context.WithCancel(context.Background())
	store.onDelete = func(w http.ResponseWriter, s *dsStore) {
		s.records = map[string]bool{}
		cancel() // caller gives up while the DELETE is in flight
		s.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		s.mu.Lock()
		io.WriteString(w, `{"code":200,"message":"Success"}`)
	}
	srv := store.serve(t)
	defer srv.Close()
	c := clientFor(srv, 5*time.Second)
	if err := c.ReplaceDS(ctx, "example.com", []*dns.DS{mkDS(1, 15, 2, "aa")}); err != nil {
		t.Fatalf("restore must run on a detached context after the caller cancelled: %v", err)
	}
	if !store.has("1") || store.has("9") {
		t.Fatalf("registrar must hold exactly the desired set, has %d records", store.count())
	}
}

func TestReplaceDS_AsynchronousAcceptanceIsVerified(t *testing.T) {
	store := newDSStore("9")
	store.pending["1"] = 2 // the PUT is accepted but becomes visible only after two GETs
	srv := store.serve(t)
	defer srv.Close()
	c := clientFor(srv, 5*time.Second)
	if err := c.ReplaceDS(context.Background(), "example.com", []*dns.DS{mkDS(1, 15, 2, "aa")}); err != nil {
		t.Fatalf("verification must wait for the accepted record to appear: %v", err)
	}
	if !store.has("1") {
		t.Fatal("desired DS must be present")
	}
}

func TestReplaceDS_UnverifiableRestoreIsAnEmergency(t *testing.T) {
	t.Run("restore PUT permanently fails", func(t *testing.T) {
		store := newDSStore("9")
		store.putFails = func(n int) bool { return n >= 2 }
		srv := store.serve(t)
		defer srv.Close()
		c := clientFor(srv, 5*time.Second)
		err := c.ReplaceDS(context.Background(), "example.com", []*dns.DS{mkDS(1, 15, 2, "aa")})
		if !errors.Is(err, ErrRegistrarDSEmpty) {
			t.Fatalf("must unwrap to ErrRegistrarDSEmpty, got %v", err)
		}
	})
	t.Run("read-back fails after restore", func(t *testing.T) {
		store := newDSStore("9")
		store.getFails = func(n int) bool { return true }
		srv := store.serve(t)
		defer srv.Close()
		c := clientFor(srv, 5*time.Second)
		err := c.ReplaceDS(context.Background(), "example.com", []*dns.DS{mkDS(1, 15, 2, "aa")})
		if !errors.Is(err, ErrRegistrarDSEmpty) {
			t.Fatalf("an unverifiable DS set must be an emergency outcome, got %v", err)
		}
	})
	t.Run("delete never dispatched", func(t *testing.T) {
		store := newDSStore("9")
		srv := store.serve(t)
		defer srv.Close()
		c := clientFor(srv, 5*time.Second)
		c.limiter = newWindowLimiter()
		ctx, cancel := context.WithCancel(context.Background())
		// Let the pre-clear PUT through, then cancel before the DELETE is gated.
		c.limiter.wait = func(ctx context.Context, d time.Duration) error { cancel(); return ctx.Err() }
		err := c.ReplaceDS(ctx, "example.com", []*dns.DS{mkDS(1, 15, 2, "aa")})
		if err == nil || errors.Is(err, ErrRegistrarDSEmpty) || !strings.Contains(err.Error(), "not sent") {
			t.Fatalf("an undispatched DELETE is an ordinary failure, got %v", err)
		}
		if store.deletes != 0 || !store.has("9") || !store.has("1") {
			t.Fatalf("nothing may be cleared when the DELETE was never sent (deletes=%d)", store.deletes)
		}
	})
}

func TestReplaceDS_ExplicitClearReconciles(t *testing.T) {
	t.Run("applied then dropped → confirmed by read-back", func(t *testing.T) {
		store := newDSStore("9")
		store.onDelete = applyThenDrop
		srv := store.serve(t)
		defer srv.Close()
		c := clientFor(srv, 5*time.Second)
		if err := c.ReplaceDS(context.Background(), "example.com", nil); err != nil {
			t.Fatalf("a clear whose deletion applied must succeed after read-back: %v", err)
		}
		if store.count() != 0 || store.puts != 0 {
			t.Fatal("explicit clear must not PUT anything")
		}
	})
	t.Run("not applied then dropped → reported, records kept", func(t *testing.T) {
		store := newDSStore("9")
		store.onDelete = func(w http.ResponseWriter, s *dsStore) { panic(http.ErrAbortHandler) }
		srv := store.serve(t)
		defer srv.Close()
		c := clientFor(srv, 5*time.Second)
		err := c.ReplaceDS(context.Background(), "example.com", nil)
		if err == nil || errors.Is(err, ErrRegistrarDSEmpty) || !strings.Contains(err.Error(), "still holds") {
			t.Fatalf("an unapplied clear must be reported plainly, got %v", err)
		}
		if !store.has("9") {
			t.Fatal("the old DS must not be touched")
		}
	})
}

// Every HTTP attempt — the initial PUT, the DELETE, each restore PUT and each
// verification GET — is admitted by the limiter, and recovery attempts run
// under the reserve.
func TestReplaceDS_EveryAttemptIsRateLimited(t *testing.T) {
	store := newDSStore("9")
	store.putFails = func(n int) bool { return n >= 2 }
	srv := store.serve(t)
	defer srv.Close()
	c := clientFor(srv, 5*time.Second)
	l, _ := clockedLimiter()
	c.limiter = l
	_ = c.ReplaceDS(context.Background(), "example.com", []*dns.DS{mkDS(1, 15, 2, "aa")})
	if store.requests == 0 || l.admissionsInWindow() != store.requests {
		t.Fatalf("limiter admitted %d, server saw %d requests; every attempt must be gated", l.admissionsInWindow(), store.requests)
	}
}

func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
