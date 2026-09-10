package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// RDAYBLUEX-010: nameserver names and addresses are canonicalized,
// de-duplicated, deterministically ordered and bounded before any work is
// scheduled, and every exceeded bound is disclosed.

func TestRDAYBLUEX010_CanonicalNameservers(t *testing.T) {
	m := newInfraMock(t)
	m.on("zone.example.", dns.TypeNS, dns.RcodeSuccess,
		&dns.NS{Hdr: hdr("zone.example.", dns.TypeNS), Ns: "NS2.zone.example."},
		&dns.NS{Hdr: hdr("zone.example.", dns.TypeNS), Ns: "ns1.zone.example."},
		&dns.NS{Hdr: hdr("zone.example.", dns.TypeNS), Ns: "ns2.ZONE.example."},
		&dns.NS{Hdr: hdr("zone.example.", dns.TypeNS), Ns: "ns1.zone.example."},
		&dns.NS{Hdr: hdr("zone.example.", dns.TypeNS), Ns: "Ns3.zone.example."})
	ns, err := m.resolver().ResolveNS(context.Background(), "zone.example.")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(ns))
	for i, n := range ns {
		got[i] = n.Name
	}
	if strings.Join(got, " ") != "ns1.zone.example. ns2.zone.example. ns3.zone.example." {
		t.Fatalf("names must be canonical, distinct and ordered: %v", got)
	}
}

func TestRDAYBLUEX010_DistinctAddresses(t *testing.T) {
	m := newInfraMock(t)
	m.on("host.example.", dns.TypeA, dns.RcodeSuccess,
		&dns.A{Hdr: hdr("host.example.", dns.TypeA), A: net.ParseIP("192.0.2.9")},
		&dns.A{Hdr: hdr("host.example.", dns.TypeA), A: net.ParseIP("192.0.2.1")},
		&dns.A{Hdr: hdr("host.example.", dns.TypeA), A: net.ParseIP("192.0.2.9")})
	m.on("host.example.", dns.TypeAAAA, dns.RcodeSuccess,
		&dns.AAAA{Hdr: hdr("host.example.", dns.TypeAAAA), AAAA: net.ParseIP("::ffff:192.0.2.1")},
		&dns.AAAA{Hdr: hdr("host.example.", dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::2")},
		&dns.AAAA{Hdr: hdr("host.example.", dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::2")})
	addrs, problems, err := m.resolver().ResolveAddressesDetailed(context.Background(), "host.example.")
	if err != nil || len(problems) != 0 {
		t.Fatalf("lookup: %v %v", problems, err)
	}
	got := make([]string, len(addrs))
	for i, a := range addrs {
		got[i] = a.String()
	}
	if strings.Join(got, " ") != "192.0.2.1 192.0.2.9 2001:db8::2" {
		t.Fatalf("repeated and IPv4-mapped duplicates collapse, in canonical order: %v", got)
	}

	u := UniqueAddresses([]string{"192.0.2.1", "::ffff:192.0.2.1", "2001:DB8::1", "2001:db8::1", "192.0.2.1", "bogus", "bogus"})
	if strings.Join(u, " ") != "192.0.2.1 2001:db8::1 bogus" {
		t.Fatalf("UniqueAddresses = %v", u)
	}
}

func TestRDAYBLUEX010_BoundsAreEnforcedAndDisclosed(t *testing.T) {
	m := newInfraMock(t)
	// More names than the bound, each duplicated; only the first
	// MaxNameserversPerZone by name may be looked up.
	var nsRRs []dns.RR
	const manyNames = 1000 // two thousand records with the case-varied duplicates
	for i := 0; i < manyNames; i++ {
		name := fmt.Sprintf("ns%03d.many.example.", i)
		nsRRs = append(nsRRs,
			&dns.NS{Hdr: hdr("many.example.", dns.TypeNS), Ns: name},
			&dns.NS{Hdr: hdr("many.example.", dns.TypeNS), Ns: strings.ToUpper(name)})
		m.on(name, dns.TypeA, dns.RcodeSuccess, &dns.A{Hdr: hdr(name, dns.TypeA), A: net.ParseIP(fmt.Sprintf("192.0.2.%d", i%200+1))})
	}
	// Two thousand records only fit a TCP message with name compression,
	// which the mock's plain handler does not enable.
	m.mu.Lock()
	m.handlers[key("many.example.", dns.TypeNS)] = func(req *dns.Msg) *dns.Msg {
		r := new(dns.Msg)
		r.Answer = nsRRs
		r.Compress = true
		return r
	}
	m.mu.Unlock()
	m.setTruncate("many.example.", dns.TypeNS)
	set, err := m.resolver().ResolveNSSet(context.Background(), "many.example.")
	if err != nil {
		t.Fatal(err)
	}
	if !set.Truncated() || len(set.Records) != MaxNameserversPerZone || len(set.Addresses) != MaxNameserversPerZone {
		t.Fatalf("names beyond the bound are not considered: %d records, %d addresses, %v", len(set.Records), len(set.Addresses), set.Truncation)
	}
	if !strings.Contains(set.Truncation[0], fmt.Sprintf("delegates %d distinct nameservers", manyNames)) {
		t.Fatalf("the truncation names the count: %v", set.Truncation)
	}
	if set.Records[0].Name != "ns000.many.example." || set.Records[MaxNameserversPerZone-1].Name != fmt.Sprintf("ns%03d.many.example.", MaxNameserversPerZone-1) {
		t.Fatalf("the first names by order are kept: %s .. %s", set.Records[0].Name, set.Records[len(set.Records)-1].Name)
	}

	// One name with more distinct addresses than the per-name bound, and a
	// zone whose distinct addresses exceed the per-zone bound; a shared
	// address is listed under each name but queried once.
	var wide []dns.RR
	for i := 0; i < MaxAddressesPerNameserver+4; i++ {
		wide = append(wide, &dns.A{Hdr: hdr("wide.example.", dns.TypeA), A: net.ParseIP(fmt.Sprintf("198.51.100.%d", i+1))})
	}
	m.on("wide.example.", dns.TypeA, dns.RcodeSuccess, wide...)
	var nsRRs2 []dns.RR
	nsRRs2 = append(nsRRs2, &dns.NS{Hdr: hdr("dense.example.", dns.TypeNS), Ns: "wide.example."})
	perName := MaxAddressesPerNameserver
	names := MaxAddressesPerZone/perName + 1 // enough names to exceed the zone bound
	for n := 0; n < names; n++ {
		name := fmt.Sprintf("h%02d.dense.example.", n)
		nsRRs2 = append(nsRRs2, &dns.NS{Hdr: hdr("dense.example.", dns.TypeNS), Ns: name})
		var rrs []dns.RR
		for i := 0; i < perName; i++ {
			rrs = append(rrs, &dns.A{Hdr: hdr(name, dns.TypeA), A: net.ParseIP(fmt.Sprintf("203.0.113.%d", n*perName+i+1))})
		}
		// Every name also shares one address with wide.example.
		rrs = append(rrs, &dns.A{Hdr: hdr(name, dns.TypeA), A: net.ParseIP("198.51.100.1")})
		m.on(name, dns.TypeA, dns.RcodeSuccess, rrs...)
	}
	m.on("dense.example.", dns.TypeNS, dns.RcodeSuccess, nsRRs2...)
	set, err = m.resolver().ResolveNSSet(context.Background(), "dense.example.")
	if err != nil {
		t.Fatal(err)
	}
	if !set.Truncated() || len(set.Addresses) != MaxAddressesPerZone {
		t.Fatalf("the zone query list stops at the bound: %d addresses, %v", len(set.Addresses), set.Truncation)
	}
	seen := map[string]int{}
	for _, a := range set.Addresses {
		seen[a]++
	}
	for a, n := range seen {
		if n != 1 {
			t.Fatalf("address %s listed %d times in the query list", a, n)
		}
	}
	var perNameNote, perZoneNote bool
	for _, note := range set.Truncation {
		if strings.Contains(note, fmt.Sprintf("only the first %d were considered", MaxAddressesPerNameserver)) {
			perNameNote = true
		}
		if strings.Contains(note, fmt.Sprintf("more than %d distinct nameserver addresses", MaxAddressesPerZone)) {
			perZoneNote = true
		}
	}
	if !perNameNote || !perZoneNote {
		t.Fatalf("both exceeded bounds are disclosed: %v", set.Truncation)
	}
	shared := 0
	for _, rec := range set.Records {
		if len(rec.Addresses) > MaxAddressesPerNameserver {
			t.Fatalf("%s keeps more than %d addresses", rec.Name, MaxAddressesPerNameserver)
		}
		for _, a := range rec.Addresses {
			if a.String() == "198.51.100.1" {
				shared++
			}
		}
	}
	if shared < 2 {
		t.Fatalf("a shared address is listed under each name that has it (%d) while queried once", shared)
	}
	// Repeated resolution is deterministic.
	again, err := m.resolver().ResolveNSSet(context.Background(), "dense.example.")
	if err != nil || strings.Join(again.Addresses, ",") != strings.Join(set.Addresses, ",") {
		t.Fatal("the query list must be identical across resolutions")
	}
}

func TestRDAYBLUEX010_ResolutionObservesCancellation(t *testing.T) {
	m := newInfraMock(t)
	var nsRRs []dns.RR
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("ns%d.slow.example.", i)
		nsRRs = append(nsRRs, &dns.NS{Hdr: hdr("slow.example.", dns.TypeNS), Ns: name})
		m.setDrop(name, dns.TypeA)
		m.setDrop(name, dns.TypeAAAA)
	}
	m.on("slow.example.", dns.TypeNS, dns.RcodeSuccess, nsRRs...)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.resolver().ResolveNSSet(ctx, "slow.example."); err == nil {
		t.Fatal("a cancelled context must end resolution with an error")
	}
}
