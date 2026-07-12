package main

import (
	"testing"
	"time"
)

// R-006: the rollover DNSKEY-TTL floor must reflect the DNSKEY TTL actually
// published (recorded per zone), not a hardcoded 24h, so a zone with dnskey_ttl=0
// and a large SOA TTL is not advanced early.
func TestR006_DNSKEYTTLFloorUsesPublishedTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNSSEC.DNSKEYTtl = 0 // "use the SOA TTL"
	rm := &RolloverManager{cfg: cfg}

	// A zone last signed with a 48h SOA-derived DNSKEY TTL.
	zs := &ZoneState{PublishedDNSKEYTTL: 172800}
	if got := rm.dnskeyTTLFloor(zs); got != 48*time.Hour {
		t.Fatalf("floor = %v, want 48h (published TTL), not the 24h hardcoded fallback", got)
	}

	// Old state without the recorded field falls back to the conservative 24h.
	if got := rm.dnskeyTTLFloor(&ZoneState{}); got != 24*time.Hour {
		t.Fatalf("floor = %v, want 24h fallback for old state", got)
	}

	// A configured TTL larger than the observed one wins (a config edit can never
	// shorten the wait).
	cfg.DNSSEC.DNSKEYTtl = 200000
	rm2 := &RolloverManager{cfg: cfg}
	if got := rm2.dnskeyTTLFloor(zs); got != 200000*time.Second {
		t.Fatalf("floor = %v, want max(config, published)=200000s", got)
	}
}

// R-007: ZSK retirement waits max(DNSKEY-TTL floor, largest signed RRset TTL) so an
// old-ZSK signature (which inherits its RRset's TTL) is never dropped while still cached.
func TestR007_ZSKRetireFloorUsesMaxRRSIGTTL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNSSEC.DNSKEYTtl = 3600 // 1h DNSKEY TTL
	rm := &RolloverManager{cfg: cfg}

	// A 7-day A record RRSIG outlives the 1h DNSKEY TTL.
	zs := &ZoneState{PublishedDNSKEYTTL: 3600, PublishedMaxRRSIGTTL: 604800}
	if got := rm.zskRetireFloor(zs); got != 604800*time.Second {
		t.Fatalf("retire floor = %v, want 7d (max signed RRset TTL), not the 1h DNSKEY TTL", got)
	}

	// When the DNSKEY TTL is the largest, it wins.
	zs2 := &ZoneState{PublishedDNSKEYTTL: 172800, PublishedMaxRRSIGTTL: 3600}
	if got := rm.zskRetireFloor(zs2); got != 172800*time.Second {
		t.Fatalf("retire floor = %v, want 48h (DNSKEY TTL is largest)", got)
	}
}
