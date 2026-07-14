package signer

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// TestSortZoneRecords_MixedCaseApexFirst (R-063): with a mixed-case zone key,
// the apex records must still sort first. Without lowercasing the apex, the
// plain name comparison would place a lexically-smaller subdomain ahead of it.
func TestSortZoneRecords_MixedCaseApexFirst(t *testing.T) {
	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 3600},
		Ns:      "ns1.example.com.",
		Mbox:    "admin.example.com.",
		Serial:  1,
		Refresh: 2, Retry: 3, Expire: 4, Minttl: 5,
	}
	aaa := &dns.A{
		Hdr: dns.RR_Header{Name: "aaa.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("192.0.2.9"),
	}

	// aaa is first in the input; "aaa.example.com." < "example.com." lexically,
	// so without the apex-first fix the SOA would not lead.
	sorted := sortZoneRecords("Example.COM", []dns.RR{aaa, soa})
	if sorted[0].Header().Name != "example.com." || sorted[0].Header().Rrtype != dns.TypeSOA {
		t.Errorf("apex SOA must sort first for a mixed-case zone key; got %s %s",
			sorted[0].Header().Name, dns.TypeToString[sorted[0].Header().Rrtype])
	}
}

// TestCanonicalLabelBytes (R-066): presentation escapes resolve to wire octets
// and ASCII is lowercased, so canonical comparison operates on wire bytes.
func TestCanonicalLabelBytes(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"www", []byte("www")},
		{"ABC", []byte("abc")},       // ASCII lowercased
		{"\\000", []byte{0}},         // decimal escape → byte 0
		{"\\200", []byte{200}},       // decimal escape → byte 200
		{"\\065", []byte("a")},       // \065 == 'A' → lowercased 'a'
		{"a\\.b", []byte("a.b")},     // escaped dot within a label
		{"\\255x", []byte{255, 'x'}}, // escape followed by a normal char
	}
	for _, c := range cases {
		got := canonicalLabelBytes(c.in)
		if string(got) != string(c.want) {
			t.Errorf("canonicalLabelBytes(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestCanonicalLess_WireOrder (R-066): names order by canonical wire-format
// octets, not presentation strings.
func TestCanonicalLess_WireOrder(t *testing.T) {
	// Wire byte 0 (\000) < 'z' (122): the escaped-octet label sorts first.
	if !canonicalLess("\\000.example.com.", "z.example.com.") {
		t.Error(`\000 label must sort before z (wire byte 0 < 122)`)
	}
	// \065 canonicalizes to 'a', so "\065.x." and "a.x." compare equal (neither less).
	if canonicalLess("\\065.x.", "a.x.") || canonicalLess("a.x.", "\\065.x.") {
		t.Error(`\065 (decimal 'A') must canonicalize to 'a' and compare equal to "a"`)
	}
	// Fewer labels sort first (shorter name is canonically smaller).
	if !canonicalLess("example.com.", "a.example.com.") {
		t.Error("the 2-label apex must sort before a 3-label subdomain")
	}
}
