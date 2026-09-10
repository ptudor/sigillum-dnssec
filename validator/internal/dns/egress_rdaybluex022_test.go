package dns

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// RDAYBLUEX-022: the public-only egress policy classifies destinations from
// an explicit globally-reachable policy. Every non-global special-purpose
// category has a vector, embedded/translated forms are judged by what they
// carry, and ordinary global unicast is not blocked.

func TestRDAYBLUEX022_NonPublicCategories(t *testing.T) {
	nonPublic := map[string]string{
		"site-local (deprecated)":      "fec0::1",
		"site-local high":              "feff:ffff::1",
		"unspecified v4":               "0.0.0.0",
		"this-network":                 "0.1.2.3",
		"private 10/8":                 "10.9.8.7",
		"CGNAT":                        "100.64.1.1",
		"loopback v4":                  "127.5.6.7",
		"link-local v4":                "169.254.9.9",
		"private 172.16/12":            "172.31.255.1",
		"IETF protocol assignments":    "192.0.0.9",
		"TEST-NET-1":                   "192.0.2.10",
		"6to4 relay anycast":           "192.88.99.1",
		"private 192.168/16":           "192.168.0.1",
		"benchmarking":                 "198.19.0.1",
		"TEST-NET-2":                   "198.51.100.7",
		"TEST-NET-3":                   "203.0.113.5",
		"multicast v4":                 "239.1.1.1",
		"reserved 240/4":               "250.0.0.1",
		"limited broadcast":            "255.255.255.255",
		"unspecified v6":               "::",
		"loopback v6":                  "::1",
		"IPv4-mapped private":          "::ffff:10.0.0.1",
		"IPv4-mapped loopback":         "::ffff:127.0.0.9",
		"NAT64 well-known":             "64:ff9b::a00:1",
		"local-use translation":        "64:ff9b:1::1",
		"discard-only":                 "100::1",
		"Teredo":                       "2001:0:1:2:3:4:5:6",
		"benchmarking v6":              "2001:2::1",
		"ORCHID":                       "2001:10::1",
		"ORCHIDv2":                     "2001:20::1",
		"documentation v6":             "2001:db8::1",
		"documentation 3fff::/20":      "3fff::1",
		"SRv6 SIDs":                    "5f00::1",
		"unique local":                 "fd12::1",
		"link-local v6":                "fe80::1",
		"multicast v6":                 "ff02::1",
		"6to4 embedding private":       "2002:0a00:0001::1", // 10.0.0.1
		"6to4 embedding loopback":      "2002:7f00:0001::1", // 127.0.0.1
		"6to4 embedding documentation": "2002:c000:0201::1", // 192.0.2.1
	}
	for name, a := range nonPublic {
		if !NonPublic(net.ParseIP(a)) {
			t.Errorf("%s (%s) must be non-public", name, a)
		}
		if err := PublicOnlyPolicy().Permit(a); err == nil {
			t.Errorf("%s (%s) must be refused by the public-only policy", name, a)
		}
	}
	global := map[string]string{
		"Cloudflare v4":         "1.1.1.1",
		"Quad9":                 "9.9.9.9",
		"Google v6":             "2001:4860:4860::8888",
		"AS112 v4 (reachable)":  "192.31.196.1",
		"AMT v4 (reachable)":    "192.52.193.1",
		"6to4 embedding global": "2002:0101:0101::1", // 1.1.1.1
		"IPv4-mapped global":    "::ffff:9.9.9.9",
		"ordinary global v6":    "2a00:1450:4001:80b::200e",
	}
	for name, a := range global {
		if NonPublic(net.ParseIP(a)) {
			t.Errorf("%s (%s) must be public", name, a)
		}
		if err := PublicOnlyPolicy().Permit(a); err != nil {
			t.Errorf("%s (%s) must be permitted: %v", name, a, err)
		}
	}
	if !NonPublic(nil) {
		t.Error("a nil address is non-public")
	}
	// An explicit allowlist still admits the deprecated range.
	allow, _ := ParseEgressAllowlist([]string{"fec0::/10"})
	p := PublicOnlyPolicy()
	p.Allow = allow
	if err := p.Permit("fec0::1"); err != nil {
		t.Fatalf("an allowlisted site-local destination must be permitted: %v", err)
	}
}

// The dial boundary: a site-local destination gets no UDP or TCP attempt
// under the public-only policy (the refusal happens before any dial), and
// an explicit allowlist is the only way to reach it.
func TestRDAYBLUEX022_SiteLocalRefusedAtDial(t *testing.T) {
	q := NewQuerier(300 * time.Millisecond)
	q.SetEgressPolicy(PublicOnlyPolicy())
	start := time.Now()
	res, err := q.Query(context.Background(), "fec0::1", "www.example.com.", dns.TypeA)
	if err != nil || !strings.Contains(res.Error, "egress policy") {
		t.Fatalf("fec0::1 must be refused by the policy, got err=%v res=%+v", err, res)
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("the refusal must happen before any dial (no timeout was spent)")
	}
	res, err = q.QueryWithRecursion(context.Background(), "[fec0::1]:53", "www.example.com.", dns.TypeA, true)
	if err != nil || !strings.Contains(res.Error, "egress policy") {
		t.Fatalf("the recursive path is refused too: err=%v res=%+v", err, res)
	}
	allow, _ := ParseEgressAllowlist([]string{"fec0::/10"})
	p := PublicOnlyPolicy()
	p.Allow = allow
	q.SetEgressPolicy(p)
	res, _ = q.Query(context.Background(), "fec0::1", "www.example.com.", dns.TypeA)
	if strings.Contains(res.Error, "egress policy") {
		t.Fatalf("once allowlisted the policy no longer refuses (the dial itself may fail): %+v", res)
	}
}
