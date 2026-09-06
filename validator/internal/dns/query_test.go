package dns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestParseResponse_DNSKEYClassification (R-095): DNSKEY flags are classified by
// BIT (Zone-Key 0x0100, SEP 0x0001, REVOKE 0x0080), not by exact equality to
// 257/256. A key that also carries the RFC 5011 REVOKE bit — or any extra flag —
// is still recognized as a KSK/ZSK and reported revoked, instead of being
// silently misclassified as neither.
func TestParseResponse_DNSKEYClassification(t *testing.T) {
	mkKey := func(flags uint16) *dns.DNSKEY {
		return &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     flags,
			Protocol:  3,
			Algorithm: 13,
			PublicKey: "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
		}
	}

	msg := new(dns.Msg)
	msg.Answer = []dns.RR{
		mkKey(257),        // KSK: Zone Key (0x0100) + SEP (0x0001)
		mkKey(256),        // ZSK: Zone Key, no SEP
		mkKey(257 | 0x80), // KSK + REVOKE (385): still Zone Key + SEP, plus REVOKE
	}

	q := NewQuerier(0)
	result := &QueryResult{}
	q.parseResponse(msg, result)

	if len(result.DNSKEY) != 3 {
		t.Fatalf("expected 3 DNSKEY records, got %d", len(result.DNSKEY))
	}
	ksk, zsk, revoked := result.DNSKEY[0], result.DNSKEY[1], result.DNSKEY[2]

	if !ksk.IsKSK || ksk.IsZSK || ksk.IsRevoked {
		t.Errorf("flags 257 should be KSK only: %+v", ksk)
	}
	if zsk.IsKSK || !zsk.IsZSK || zsk.IsRevoked {
		t.Errorf("flags 256 should be ZSK only: %+v", zsk)
	}
	// The revoked key keeps Zone Key + SEP set, so it remains a KSK; the fix
	// additionally surfaces IsRevoked. Strict ==257 previously classified it as
	// neither KSK nor ZSK.
	if !revoked.IsKSK || revoked.IsZSK || !revoked.IsRevoked {
		t.Errorf("flags 257|REVOKE should be KSK + revoked: %+v", revoked)
	}
}
