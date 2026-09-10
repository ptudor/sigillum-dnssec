package validator

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// RDAYBLUEX-010: authoritative fan-out is bounded. Distinct addresses are
// queried once through a fixed-size worker pool that observes cancellation,
// and a delegation beyond the bounds is examined through a disclosed subset
// that can never become Secure.

// authoritativeQuestions returns every question the mock received without
// the RD flag: the validator's direct dials to authoritative servers.
func (m *mockDNS) authoritativeQuestions() []dns.Question {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []dns.Question
	for i, q := range m.seen {
		if !m.seenRecursive[i] {
			out = append(out, q)
		}
	}
	return out
}

// TestRDAYBLUEX010_BoundedPool is the resource-bound regression: thousands
// of jobs, a handful of workers, fixed goroutine growth, and cancellation
// that stops queued jobs from starting. It is repeated so the race detector
// sees the hand-off many times.
func TestRDAYBLUEX010_BoundedPool(t *testing.T) {
	for round := 0; round < 20; round++ {
		const jobs, workers = 5000, 4
		var inflight, peak, started atomic.Int32
		gate := make(chan struct{})
		before := runtime.NumGoroutine()
		done := make(chan struct{})
		go func() {
			runBounded(context.Background(), jobs, workers, func(int) {
				started.Add(1)
				cur := inflight.Add(1)
				for {
					p := peak.Load()
					if cur <= p || peak.CompareAndSwap(p, cur) {
						break
					}
				}
				<-gate
				inflight.Add(-1)
			})
			close(done)
		}()
		// Wait until every worker is busy, then measure goroutine growth.
		deadline := time.Now().Add(5 * time.Second)
		for inflight.Load() < workers && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if grown := runtime.NumGoroutine() - before; grown > workers+2 {
			t.Fatalf("round %d: %d jobs must not create %d goroutines (workers %d)", round, jobs, grown, workers)
		}
		close(gate)
		<-done
		if started.Load() != jobs || peak.Load() > workers {
			t.Fatalf("round %d: started %d of %d, peak concurrency %d (limit %d)", round, started.Load(), jobs, peak.Load(), workers)
		}
	}

	// Cancellation: once the context ends, no queued job starts and the pool
	// returns promptly after the running jobs finish.
	ctx, cancel := context.WithCancel(context.Background())
	var started atomic.Int32
	release := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		runBounded(ctx, 1000, 3, func(int) {
			started.Add(1)
			<-release
		})
		close(finished)
	}()
	for started.Load() < 3 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	close(release)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the pool must return after cancellation")
	}
	if n := started.Load(); n > 3+3 {
		t.Fatalf("after cancellation queued jobs must not start, %d started", n)
	}
	// Degenerate sizes are safe.
	runBounded(context.Background(), 0, 4, func(int) { t.Fatal("no job for n = 0") })
	var one atomic.Int32
	runBounded(context.Background(), 1, 0, func(int) { one.Add(1) })
	if one.Load() != 1 {
		t.Fatal("workers <= 0 still runs the job once")
	}
}

// TestRDAYBLUEX010_DistinctAddressesQueriedOnce: many names sharing an
// address, repeated RRs, case-varied names and an IPv4-mapped duplicate all
// collapse to one query per distinct address, deterministically ordered.
func TestRDAYBLUEX010_DistinctAddressesQueriedOnce(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "shared.test.")
	ip := net.ParseIP(f.m.ip)
	var nsRRs []dns.RR
	names := []string{"B.shared.test.", "a.shared.test.", "A.SHARED.test.", "c.shared.test.", "b.shared.test."}
	for _, n := range names {
		nsRRs = append(nsRRs, &dns.NS{Hdr: rrHdr("shared.test.", dns.TypeNS), Ns: n})
	}
	f.m.answer("shared.test.", dns.TypeNS, nsRRs...)
	for _, n := range []string{"a.shared.test.", "b.shared.test.", "c.shared.test."} {
		// Repeated RRs and the mapped form of the same address.
		f.m.answer(n, dns.TypeA,
			&dns.A{Hdr: rrHdr(n, dns.TypeA), A: ip},
			&dns.A{Hdr: rrHdr(n, dns.TypeA), A: ip},
			&dns.A{Hdr: rrHdr(n, dns.TypeA), A: ip.To16()})
	}
	leaf := &dns.A{Hdr: rrHdr("shared.test.", dns.TypeA), A: net.ParseIP("192.0.2.10")}
	f.m.answer("shared.test.", dns.TypeA, leaf, child.signZSK(t, leaf))
	res := f.validate(t, "shared.test.")
	if res.Result != StatusSecure {
		t.Fatalf("a delegation within the bounds validates normally, got %s: %v", res.Result, res.Errors)
	}
	var zone *ZoneResult
	for i := range res.Chain {
		if res.Chain[i].Zone == "shared.test." {
			zone = &res.Chain[i]
		}
	}
	if zone == nil {
		t.Fatal("zone result missing")
	}
	if len(zone.Nameservers) != 3 || zone.Nameservers[0].Name != "a.shared.test." || zone.Nameservers[2].Name != "c.shared.test." {
		t.Fatalf("nameservers must be canonical, distinct and ordered: %+v", zone.Nameservers)
	}
	for _, ns := range zone.Nameservers {
		if len(ns.Addresses) != 1 || ns.Addresses[0].IP != f.m.ip || ns.Addresses[0].Status != StatusSecure {
			t.Fatalf("each name lists its one distinct address with the shared verdict: %+v", ns)
		}
	}
	dnskeyQueries := 0
	for _, q := range f.m.authoritativeQuestions() {
		if q.Qtype == dns.TypeDNSKEY && dns.CanonicalName(q.Name) == "shared.test." {
			dnskeyQueries++
		}
	}
	if dnskeyQueries != 1 {
		t.Fatalf("one address shared by three names must be queried once, got %d DNSKEY queries", dnskeyQueries)
	}
}

// TestRDAYBLUEX010_OversizedDelegationIsDisclosedNotSecure: a delegation of
// a thousand nameserver names (two thousand records with the case-varied
// duplicates, the largest answer a TCP message can carry) is bounded before any
// address lookup, the subset is disclosed, resolver queries stay bounded,
// and the zone is Indeterminate even though the queried server serves a
// perfectly valid signed DNSKEY.
func TestRDAYBLUEX010_OversizedDelegationIsDisclosedNotSecure(t *testing.T) {
	f := newChainFixture(t)
	big := f.addChild(t, "big.test.")
	leaf := &dns.A{Hdr: rrHdr("big.test.", dns.TypeA), A: net.ParseIP("192.0.2.10")}
	f.m.answer("big.test.", dns.TypeA, leaf, big.signZSK(t, leaf))
	ip := net.ParseIP(f.m.ip)
	var nsRRs []dns.RR
	for i := 0; i < 1000; i++ {
		name := fmt.Sprintf("ns%04d.big.test.", i)
		nsRRs = append(nsRRs,
			&dns.NS{Hdr: rrHdr("big.test.", dns.TypeNS), Ns: name},
			&dns.NS{Hdr: rrHdr("big.test.", dns.TypeNS), Ns: strings.ToUpper(name)})
		if i < 64 {
			f.m.answer(name, dns.TypeA, &dns.A{Hdr: rrHdr(name, dns.TypeA), A: ip})
		}
	}
	// Two thousand records only fit a TCP message with name compression.
	f.m.on("big.test.", dns.TypeNS, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = nsRRs
		resp.Compress = true
		return resp
	})
	f.m.truncateOverUDP("big.test.", dns.TypeNS)

	res := f.validate(t, "big.test.")
	if res.Result == StatusSecure {
		t.Fatal("a truncated nameserver set must never yield Secure")
	}
	var zone *ZoneResult
	for i := range res.Chain {
		if res.Chain[i].Zone == "big.test." {
			zone = &res.Chain[i]
		}
	}
	if zone == nil || zone.Status != StatusIndeterminate {
		t.Fatalf("the truncated zone must be Indeterminate: %+v", zone)
	}
	if len(zone.Errors) == 0 || !strings.Contains(zone.Errors[0], "fan-out bounds") {
		t.Fatalf("the exceeded budget must be reported: %v", zone.Errors)
	}
	found := false
	for _, w := range zone.Warnings {
		if strings.Contains(w, "delegates 1000 distinct nameservers") && strings.Contains(w, fmt.Sprintf("first %d", dnspkg.MaxNameserversPerZone)) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the truncation must name the bound and the count: %v", zone.Warnings)
	}
	if len(zone.Nameservers) != dnspkg.MaxNameserversPerZone {
		t.Fatalf("the disclosed subset is what was considered: %d names", len(zone.Nameservers))
	}
	// Resolver queries were bounded: address lookups for the subset only.
	lookups := map[string]bool{}
	for _, q := range f.m.questions() {
		if (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA) && strings.HasSuffix(dns.CanonicalName(q.Name), ".big.test.") {
			lookups[dns.CanonicalName(q.Name)] = true
		}
	}
	if len(lookups) != dnspkg.MaxNameserversPerZone {
		t.Fatalf("address lookups must stop at the bound: %d names looked up", len(lookups))
	}
	for _, ns := range zone.Nameservers {
		for _, a := range ns.Addresses {
			if a.Status == StatusSecure || a.Status == StatusValidating {
				t.Fatalf("no server in a truncated set is judged: %+v", a)
			}
		}
	}
}

// TestRDAYBLUEX010_CancellationStopsQueuedQueries: with slow authoritative
// servers, cancelling the validation prevents queued DNSKEY queries from
// being sent.
func TestRDAYBLUEX010_CancellationStopsQueuedQueries(t *testing.T) {
	m := newMockDNS(t)
	v := m.newValidatorWithTimeout(2 * time.Second)
	v.maxConcurrent = 1
	var sent atomic.Int32
	block := make(chan struct{})
	m.on("slow.test.", dns.TypeDNSKEY, func(req *dns.Msg) *dns.Msg {
		sent.Add(1)
		<-block
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	servers := []string{m.ip, m.ip, m.ip} // de-duplicated to one
	if m.enableDualStack(t) {
		servers = append(servers, "::1", "::1")
	}
	var results []AddressResult
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		results = v.ValidateMultipleServers(ctx, "slow.test.", servers)
	}()
	for sent.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	close(block)
	wg.Wait()
	if len(results) != len(dnspkg.UniqueAddresses(servers)) {
		t.Fatalf("one result per distinct address, got %d", len(results))
	}
	if sent.Load() != 1 {
		t.Fatalf("after cancellation no queued query may be sent, %d sent", sent.Load())
	}
	for _, r := range results[1:] {
		if r.Status != StatusIndeterminate || !strings.Contains(r.Error, "not queried") {
			t.Fatalf("an unqueried server is reported as such: %+v", r)
		}
	}
}
