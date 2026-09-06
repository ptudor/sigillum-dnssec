package dns

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// RA6X-007: every parsed record must carry its owner, class and message
// section so consumers can keep Answer data, Authority denial records and
// Additional junk apart instead of consuming one merged slice.
func TestRA6X007_ParseResponseCarriesOwnerClassSection(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeDS)
	msg.Answer = []dns.RR{
		&dns.DS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}, KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: "aa"},
		&dns.RRSIG{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300}, TypeCovered: dns.TypeDS, Algorithm: 13, Labels: 1, SignerName: "com.", Signature: "AA=="},
	}
	msg.Ns = []dns.RR{
		&dns.NSEC{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300}, NextDomain: "z.com.", TypeBitMap: []uint16{dns.TypeNS}},
		&dns.NSEC3{Hdr: dns.RR_Header{Name: "ABCD.com.", Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300}, Hash: 1, NextDomain: "EFGH", TypeBitMap: []uint16{dns.TypeNS}},
		&dns.NS{Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300}, Ns: "a.gtld-servers.net."},
	}
	msg.Extra = []dns.RR{
		&dns.DS{Hdr: dns.RR_Header{Name: "unrelated.invalid.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300}, KeyTag: 2, Algorithm: 13, DigestType: 2, Digest: "bb"},
		&dns.DNSKEY{Hdr: dns.RR_Header{Name: "unrelated.invalid.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 300}, Flags: 257, Protocol: 3, Algorithm: 13, PublicKey: "AA=="},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.invalid.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "target.invalid."},
		&dns.A{Hdr: dns.RR_Header{Name: "a.gtld-servers.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.1")},
	}

	q := NewQuerier(0)
	result := &QueryResult{}
	q.parseResponse(msg, result)

	if len(result.DS) != 2 {
		t.Fatalf("DS count = %d, want 2 (both sections parsed for display)", len(result.DS))
	}
	if result.DS[0].Section != SectionAnswer || result.DS[0].Owner != "example.com." || result.DS[0].Class != dns.ClassINET {
		t.Errorf("Answer DS metadata = %+v", result.DS[0])
	}
	if result.DS[1].Section != SectionAdditional || result.DS[1].Owner != "unrelated.invalid." {
		t.Errorf("Additional DS metadata = %+v", result.DS[1])
	}
	if len(result.RRSIG) != 1 || result.RRSIG[0].Section != SectionAnswer || result.RRSIG[0].Owner != "example.com." {
		t.Errorf("RRSIG metadata = %+v", result.RRSIG)
	}
	if len(result.NSEC) != 1 || result.NSEC[0].Section != SectionAuthority || result.NSEC[0].Owner != "example.com." {
		t.Errorf("NSEC metadata = %+v", result.NSEC)
	}
	if len(result.NSEC3) != 1 || result.NSEC3[0].Section != SectionAuthority || result.NSEC3[0].Owner != "ABCD.com." {
		t.Errorf("NSEC3 metadata = %+v", result.NSEC3)
	}
	if len(result.NS) != 1 || result.NS[0].Section != SectionAuthority || result.NS[0].Owner != "com." {
		t.Errorf("NS metadata = %+v", result.NS)
	}
	if len(result.DNSKEY) != 1 || result.DNSKEY[0].Section != SectionAdditional || result.DNSKEY[0].Owner != "unrelated.invalid." {
		t.Errorf("DNSKEY metadata = %+v", result.DNSKEY)
	}
	if len(result.CNAME) != 1 || result.CNAME[0].Section != SectionAdditional || result.CNAME[0].Name != "alias.invalid." {
		t.Errorf("CNAME metadata = %+v", result.CNAME)
	}
}

func TestRA6X007_InSection(t *testing.T) {
	if !InSection(SectionAnswer, SectionAnswer) || InSection(SectionAdditional, SectionAnswer) {
		t.Error("InSection must match the recorded section exactly")
	}
	if !InSection(SectionAuthority, SectionAuthority, SectionAnswer) {
		t.Error("InSection must accept any listed section")
	}
	// A record built in-process (no section) is accepted so direct callers keep
	// working; a parsed record always carries its real section.
	if !InSection("", SectionAnswer) {
		t.Error("unknown section must be accepted")
	}
	if InSection("") {
		t.Error("no allowed sections must never match")
	}
}
