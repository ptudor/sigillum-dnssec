package dns

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// delayedDeadlineContext models the interval after a socket deadline expires
// but before the context timer publishes its cancellation signal.
type delayedDeadlineContext struct {
	context.Context
	deadline time.Time
}

func (c delayedDeadlineContext) Deadline() (time.Time, bool) { return c.deadline, true }

func TestDiscoverZoneCutsDeadlineBeforeContextSignal(t *testing.T) {
	m := newInfraMock(t)
	m.setDrop("test.", dns.TypeNS)
	ctx := delayedDeadlineContext{
		Context:  context.Background(),
		deadline: time.Now().Add(50 * time.Millisecond),
	}
	zones, err := m.resolver().DiscoverZoneCuts(ctx, "www.child.test.")
	if !errors.Is(err, context.DeadlineExceeded) || zones != nil {
		t.Fatalf("expired discovery = %v, %v; want no chain and DeadlineExceeded", zones, err)
	}
}

func TestDiscoverZoneCutsAlreadyCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := NewResolver(time.Second, "127.0.0.1")
	for _, domain := range []string{".", "www.child.test."} {
		zones, err := r.DiscoverZoneCuts(ctx, domain)
		if !errors.Is(err, context.Canceled) || zones != nil {
			t.Fatalf("cancelled discovery of %s = %v, %v; want no chain and Canceled", domain, zones, err)
		}
	}
}

func TestDiscoverZoneCutsQueryTimeoutKeepsCandidate(t *testing.T) {
	m := newInfraMock(t)
	m.setDrop("test.", dns.TypeNS)
	r := m.resolver()
	r.querier.timeout = 20 * time.Millisecond
	zones, err := r.DiscoverZoneCuts(context.Background(), "test.")
	if err != nil || len(zones) != 2 || zones[0] != "." || zones[1] != "test." {
		t.Fatalf("query timeout with live context = %v, %v; want root and candidate", zones, err)
	}
}
