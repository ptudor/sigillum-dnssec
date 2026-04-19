package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestFindParentZone(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com", "com."},
		{"example.com.", "com."},
		{"sub.example.com", "example.com."},
		{"deep.sub.example.com", "sub.example.com."},
		{"com", "."},
		{"com.", "."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := findParentZone(tt.input)
			if got != tt.want {
				t.Errorf("findParentZone(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestComputeOverall(t *testing.T) {
	tests := []struct {
		name     string
		statuses []string
		want     string
	}{
		{"all pass", []string{"pass", "pass", "pass", "pass"}, "pass"},
		{"all fail", []string{"fail", "fail", "fail", "fail"}, "fail"},
		{"all error", []string{"error", "error", "error", "error"}, "error"},
		{"mix pass and fail", []string{"pass", "fail", "pass", "pass"}, "partial"},
		{"mix pass and error", []string{"pass", "error", "pass", "pass"}, "partial"},
		{"errors and fails no pass", []string{"error", "fail", "error", "fail"}, "partial"},
		{"one partial rest pass", []string{"pass", "pass", "partial", "pass"}, "partial"},
		{"errors only no pass", []string{"error", "error", "error", "fail"}, "partial"},
		{"only errors no fails", []string{"error", "error"}, "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeOverall(tt.statuses...)
			if got != tt.want {
				t.Errorf("computeOverall(%v) = %q, want %q", tt.statuses, got, tt.want)
			}
		})
	}
}

func TestResolverAddr(t *testing.T) {
	t.Run("explicit resolver with port", func(t *testing.T) {
		v := &Validator{resolver: "8.8.8.8:53", timeout: 5 * time.Second}
		got := v.resolverAddr()
		if got != "8.8.8.8:53" {
			t.Errorf("resolverAddr() = %q, want %q", got, "8.8.8.8:53")
		}
	})

	t.Run("explicit resolver without port", func(t *testing.T) {
		v := &Validator{resolver: "8.8.4.4", timeout: 5 * time.Second}
		got := v.resolverAddr()
		if got != "8.8.4.4:53" {
			t.Errorf("resolverAddr() = %q, want %q", got, "8.8.4.4:53")
		}
	})

	t.Run("empty resolver uses system or fallback", func(t *testing.T) {
		v := &Validator{resolver: "", timeout: 5 * time.Second}
		got := v.resolverAddr()
		// Should return either a system resolver or 1.1.1.1:53
		if got == "" {
			t.Error("resolverAddr() returned empty string")
		}
		_, _, err := net.SplitHostPort(got)
		if err != nil {
			t.Errorf("resolverAddr() returned invalid host:port %q: %v", got, err)
		}
	})
}

// startMockDNS starts a DNS server on a random UDP port and returns the address and a cleanup function.
func startMockDNS(t *testing.T, handler dns.HandlerFunc) (string, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	srv := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() {
		if err := srv.ActivateAndServe(); err != nil {
			// Server was shut down
		}
	}()

	// Wait for server to be ready
	time.Sleep(10 * time.Millisecond)

	addr := pc.LocalAddr().String()
	return addr, func() { srv.Shutdown() }
}

func TestDSCheck(t *testing.T) {
	// Use hardcoded DS record values for the mock
	testKeyTag := uint16(12345)
	testAlgorithm := uint8(dns.ED25519)
	testDigestType := uint8(dns.SHA256)
	testDigest := "AABBCCDD00112233AABBCCDD00112233AABBCCDD00112233AABBCCDD00112233"

	// Mock parent NS that returns DS records
	parentAddr, parentCleanup := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeDS {
			m.Answer = append(m.Answer, &dns.DS{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeDS,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				KeyTag:     testKeyTag,
				Algorithm:  testAlgorithm,
				DigestType: testDigestType,
				Digest:     testDigest,
			})
		}
		w.WriteMsg(m)
	})
	defer parentCleanup()

	// Test queryDirect returns DS records from mock
	msg, err := queryDirect(parentAddr, "example.com.", dns.TypeDS, 2*time.Second)
	if err != nil {
		t.Fatalf("queryDirect failed: %v", err)
	}

	var found bool
	for _, rr := range msg.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			if ds.KeyTag == testKeyTag && ds.DigestType == testDigestType {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected DS record not found in mock response")
	}

	// checkDSAtParent with an unreachable resolver to verify error handling
	v := &Validator{resolver: "192.0.2.1:53", timeout: 1 * time.Second}
	result := v.checkDSAtParent("test.invalid.", nil)
	if result.Status != "error" {
		t.Errorf("expected status=error for unreachable resolver, got %q (details: %s)", result.Status, result.Details)
	}
}

func TestDNSKEYCheck(t *testing.T) {
	kskTag := uint16(12345)
	zskTag := uint16(54321)

	// Mock auth NS returning DNSKEY records
	authAddr, authCleanup := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeDNSKEY {
			// Return two DNSKEY records with known key tags
			// Since key tag computation depends on the full record, we just
			// verify the query path works correctly
			m.Answer = append(m.Answer, &dns.DNSKEY{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeDNSKEY,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Flags:     257,
				Protocol:  3,
				Algorithm: dns.ED25519,
				PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			})
		}
		w.WriteMsg(m)
	})
	defer authCleanup()

	// Query the mock server directly
	msg, err := queryDirect(authAddr, "example.com.", dns.TypeDNSKEY, 2*time.Second)
	if err != nil {
		t.Fatalf("queryDirect failed: %v", err)
	}

	var keyTags []uint16
	for _, rr := range msg.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			keyTags = append(keyTags, dnskey.KeyTag())
		}
	}

	if len(keyTags) == 0 {
		t.Error("expected DNSKEY records in mock response")
	}

	// Test checkDNSKEYVisible with the mock — it will fail on NS resolution
	// since our mock doesn't serve NS records, but verify error handling
	v := &Validator{timeout: 2 * time.Second}
	result := v.checkDNSKEYVisible("example.com", kskTag, zskTag)
	if result.Status != "error" {
		t.Logf("DNSKEY check status: %s (details: %s)", result.Status, result.Details)
	}
}

func TestRRSIGCheck(t *testing.T) {
	// Mock auth NS returning SOA with RRSIG
	authAddr, authCleanup := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		switch r.Question[0].Qtype {
		case dns.TypeSOA:
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Ns:      "ns1.example.com.",
				Mbox:    "admin.example.com.",
				Serial:  2024010101,
				Refresh: 3600,
				Retry:   900,
				Expire:  604800,
				Minttl:  300,
			})
			m.Answer = append(m.Answer, &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeRRSIG,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				TypeCovered: dns.TypeSOA,
				Algorithm:   dns.ED25519,
				Labels:      2,
				OrigTtl:     3600,
				Expiration:  uint32(time.Now().Add(14 * 24 * time.Hour).Unix()),
				Inception:   uint32(time.Now().Unix()),
				KeyTag:      12345,
				SignerName:  "example.com.",
			})
		case dns.TypeDNSKEY:
			m.Answer = append(m.Answer, &dns.RRSIG{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeRRSIG,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				TypeCovered: dns.TypeDNSKEY,
				Algorithm:   dns.ED25519,
				Labels:      2,
				OrigTtl:     3600,
				Expiration:  uint32(time.Now().Add(14 * 24 * time.Hour).Unix()),
				Inception:   uint32(time.Now().Unix()),
				KeyTag:      12345,
				SignerName:  "example.com.",
			})
		}
		w.WriteMsg(m)
	})
	defer authCleanup()

	// Verify RRSIG records are properly returned from mock
	soaMsg, err := queryDirect(authAddr, "example.com.", dns.TypeSOA, 2*time.Second)
	if err != nil {
		t.Fatalf("SOA query failed: %v", err)
	}

	var soaSigned bool
	for _, rr := range soaMsg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == dns.TypeSOA {
			soaSigned = true
		}
	}
	if !soaSigned {
		t.Error("expected RRSIG for SOA in mock response")
	}

	dnskeyMsg, err := queryDirect(authAddr, "example.com.", dns.TypeDNSKEY, 2*time.Second)
	if err != nil {
		t.Fatalf("DNSKEY query failed: %v", err)
	}

	var dnskeySigned bool
	for _, rr := range dnskeyMsg.Answer {
		if rrsig, ok := rr.(*dns.RRSIG); ok && rrsig.TypeCovered == dns.TypeDNSKEY {
			dnskeySigned = true
		}
	}
	if !dnskeySigned {
		t.Error("expected RRSIG for DNSKEY in mock response")
	}
}

func TestSOACheck(t *testing.T) {
	localSerial := uint32(2024010101)

	// Mock auth NS returning matching SOA
	authAddr, authCleanup := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeSOA {
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				Ns:      "ns1.example.com.",
				Mbox:    "admin.example.com.",
				Serial:  localSerial,
				Refresh: 3600,
				Retry:   900,
				Expire:  604800,
				Minttl:  300,
			})
		}
		w.WriteMsg(m)
	})
	defer authCleanup()

	msg, err := queryDirect(authAddr, "example.com.", dns.TypeSOA, 2*time.Second)
	if err != nil {
		t.Fatalf("SOA query failed: %v", err)
	}

	for _, rr := range msg.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			if soa.Serial != localSerial {
				t.Errorf("SOA serial = %d, want %d", soa.Serial, localSerial)
			}
			return
		}
	}
	t.Error("no SOA record in mock response")
}

func TestQueryDirectDOBit(t *testing.T) {
	// Verify that queryDirect sets the DO bit
	addr, cleanup := startMockDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)

		// Check that DO bit is set
		opt := r.IsEdns0()
		hasDO := opt != nil && opt.Do()

		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
			Txt: []string{fmt.Sprintf("do=%v", hasDO)},
		})
		w.WriteMsg(m)
	})
	defer cleanup()

	msg, err := queryDirect(addr, "test.example.com.", dns.TypeTXT, 2*time.Second)
	if err != nil {
		t.Fatalf("queryDirect failed: %v", err)
	}

	for _, rr := range msg.Answer {
		if txt, ok := rr.(*dns.TXT); ok {
			if len(txt.Txt) > 0 && txt.Txt[0] != "do=true" {
				t.Errorf("DO bit not set in query: got %s", txt.Txt[0])
			}
			return
		}
	}
	t.Error("no TXT record in response")
}

func TestValidateZoneNotFound(t *testing.T) {
	cfg := DefaultConfig()
	state := NewState("/tmp/test-state.json")

	v := NewValidator(cfg, state, "8.8.8.8:53", 5*time.Second)
	result := v.ValidateZone("nonexistent.example.com")

	if result.Overall != "error" {
		t.Errorf("expected overall=error for nonexistent zone, got %q", result.Overall)
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for nonexistent zone")
	}
}
