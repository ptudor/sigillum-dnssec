package validator

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// R-083: the documented `type` parameter is parsed and validated against a
// supported set (empty defaults to A; unsupported types are rejected).
func TestSupportedQueryType(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
		ok   bool
	}{
		{"", dns.TypeA, true},
		{"A", dns.TypeA, true},
		{"aaaa", dns.TypeAAAA, true},
		{"MX", dns.TypeMX, true},
		{"txt", dns.TypeTXT, true},
		{"CNAME", dns.TypeCNAME, true},
		{"ANY", 0, false},
		{"AXFR", 0, false},
		{"garbage", 0, false},
	}
	for _, c := range cases {
		got, ok := SupportedQueryType(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("SupportedQueryType(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// R-083: leafTypeName reflects the configured type.
func TestValidatorLeafTypeName(t *testing.T) {
	v := &Validator{}
	if v.leafTypeName() != "A" {
		t.Errorf("default leaf type = %q, want A", v.leafTypeName())
	}
	v.SetQueryType(dns.TypeMX)
	if v.leafTypeName() != "MX" {
		t.Errorf("after SetQueryType(MX): %q, want MX", v.leafTypeName())
	}
}

// R-100: leafFingerprint compares the answer across servers, ignoring benign TTL
// differences and flagging genuinely different answers.
func TestLeafFingerprint(t *testing.T) {
	v := &Validator{queryType: dns.TypeA}
	mk := func(ip string, ttl uint32) *dnspkg.QueryResult {
		m := new(dns.Msg)
		m.SetQuestion("www.example.com.", dns.TypeA)
		m.Rcode = dns.RcodeSuccess
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   net.ParseIP(ip),
		}}
		raw, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return &dnspkg.QueryResult{RCodeName: "NOERROR", RawResponse: raw}
	}

	a := mk("192.0.2.1", 300)
	aTTL := mk("192.0.2.1", 60)
	b := mk("192.0.2.99", 300)

	if v.leafFingerprint(a) != v.leafFingerprint(aTTL) {
		t.Error("same answer, different TTL must fingerprint identically (no false disagreement)")
	}
	if v.leafFingerprint(a) == v.leafFingerprint(b) {
		t.Error("different answers must fingerprint differently (R-100 disagreement)")
	}
}
