package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestParseResponseAnswerTypes: AnswerTypes must reflect only the ANSWER
// section — deduplicated, in response order — so callers can distinguish a
// positive answer (e.g. a wildcard expansion whose NSEC/NSEC3 proof rides in
// the authority section) from a NODATA denial (empty answer).
func TestParseResponseAnswerTypes(t *testing.T) {
	const qname = "host.example.com."
	hdr := func(rrtype uint16) dns.RR_Header {
		return dns.RR_Header{Name: qname, Rrtype: rrtype, Class: dns.ClassINET, Ttl: 300}
	}
	mkSig := func(covered uint16) *dns.RRSIG {
		return &dns.RRSIG{
			Hdr:         hdr(dns.TypeRRSIG),
			TypeCovered: covered,
			Algorithm:   13,
			Labels:      2,
			OrigTtl:     300,
			Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
			Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
			KeyTag:      12345,
			SignerName:  "example.com.",
			Signature:   "MEUCIQ==",
		}
	}
	nsec := &dns.NSEC{
		Hdr:        hdr(dns.TypeNSEC),
		NextDomain: "z.example.com.",
		TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC},
	}

	// Wildcard-shaped positive answer: A records + RRSIG in ANSWER, NSEC +
	// RRSIG in AUTHORITY.
	msg := new(dns.Msg)
	msg.SetQuestion(qname, dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{Hdr: hdr(dns.TypeA), A: net.IPv4(192, 0, 2, 1)},
		&dns.A{Hdr: hdr(dns.TypeA), A: net.IPv4(192, 0, 2, 2)},
		mkSig(dns.TypeA),
	}
	msg.Ns = []dns.RR{nsec, mkSig(dns.TypeNSEC)}

	q := NewQuerier(0)
	result := &QueryResult{}
	q.parseResponse(msg, result)

	want := []uint16{dns.TypeA, dns.TypeRRSIG}
	if len(result.AnswerTypes) != len(want) {
		t.Fatalf("AnswerTypes = %v, want %v", result.AnswerTypes, want)
	}
	for i, tt := range want {
		if result.AnswerTypes[i] != tt {
			t.Fatalf("AnswerTypes = %v, want %v", result.AnswerTypes, want)
		}
	}
	// The authority-section NSEC is still parsed, but must not leak into
	// AnswerTypes.
	if len(result.NSEC) != 1 {
		t.Fatalf("expected the authority NSEC to be parsed, got %d NSEC records", len(result.NSEC))
	}

	// NODATA-shaped response: empty ANSWER, NSEC + RRSIG in AUTHORITY.
	nodata := new(dns.Msg)
	nodata.SetQuestion(qname, dns.TypeA)
	nodata.Ns = []dns.RR{nsec, mkSig(dns.TypeNSEC)}

	result2 := &QueryResult{}
	q.parseResponse(nodata, result2)
	if len(result2.AnswerTypes) != 0 {
		t.Fatalf("empty answer section must yield no AnswerTypes, got %v", result2.AnswerTypes)
	}
}
