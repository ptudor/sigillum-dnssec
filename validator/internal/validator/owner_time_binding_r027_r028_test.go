package validator

import (
	"net"
	"testing"
	"time"

	miekgdns "github.com/miekg/dns"
)

// R-027: a cryptographically valid A RRset for a DIFFERENT owner, replayed in the
// Additional section, must not authenticate the queried name.
func TestR027_LeafBoundToAnswerOwner(t *testing.T) {
	const zone = "example.com."
	key, signer, rec := genTestDNSKEY(t, zone, 256)

	a := &miekgdns.A{Hdr: miekgdns.RR_Header{Name: "other.example.com.", Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 9).To4()}
	sig := &miekgdns.RRSIG{
		Hdr:         miekgdns.RR_Header{Name: "other.example.com.", Rrtype: miekgdns.TypeRRSIG, Class: miekgdns.ClassINET, Ttl: 300},
		TypeCovered: miekgdns.TypeA, Algorithm: key.Algorithm, Labels: uint8(miekgdns.CountLabel("other.example.com.")),
		OrigTtl: 300, Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()), Inception: uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag: key.KeyTag(), SignerName: zone,
	}
	if err := sig.Sign(signer, []miekgdns.RR{a}); err != nil {
		t.Fatalf("sign A: %v", err)
	}

	// Legit RRset for other.example.com placed in Additional; query is www.example.com.
	badMsg := new(miekgdns.Msg)
	badMsg.SetQuestion("www.example.com.", miekgdns.TypeA)
	badMsg.Extra = []miekgdns.RR{a, sig}
	badRaw, _ := badMsg.Pack()
	if _, err := VerifyRRsetRRSIGFromResponse(badRaw, miekgdns.TypeA, rec, key.KeyTag(), "www.example.com.", true); err == nil {
		t.Fatal("a valid RRset for another owner in Additional must not authenticate the queried name")
	}

	// Same RRset in Answer at its true owner verifies.
	goodMsg := new(miekgdns.Msg)
	goodMsg.SetQuestion("other.example.com.", miekgdns.TypeA)
	goodMsg.Answer = []miekgdns.RR{a, sig}
	goodRaw, _ := goodMsg.Pack()
	if _, err := VerifyRRsetRRSIGFromResponse(goodRaw, miekgdns.TypeA, rec, key.KeyTag(), "other.example.com.", true); err != nil {
		t.Fatalf("valid Answer RRset at the queried owner must verify: %v", err)
	}
}

// R-028: an expired but cryptographically valid signature must be rejected because
// the time check is bound to the same candidate signature.
func TestR028_ExpiredSignatureRejected(t *testing.T) {
	const zone = "example.com."
	key, signer, rec := genTestDNSKEY(t, zone, 256)

	a := &miekgdns.A{Hdr: miekgdns.RR_Header{Name: "host.example.com.", Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 300}, A: net.IPv4(192, 0, 2, 9).To4()}
	expired := &miekgdns.RRSIG{
		Hdr:         miekgdns.RR_Header{Name: "host.example.com.", Rrtype: miekgdns.TypeRRSIG, Class: miekgdns.ClassINET, Ttl: 300},
		TypeCovered: miekgdns.TypeA, Algorithm: key.Algorithm, Labels: uint8(miekgdns.CountLabel("host.example.com.")),
		OrigTtl:    300,
		Expiration: uint32(time.Now().Add(-48 * time.Hour).Unix()),
		Inception:  uint32(time.Now().Add(-72 * time.Hour).Unix()),
		KeyTag:     key.KeyTag(), SignerName: zone,
	}
	if err := expired.Sign(signer, []miekgdns.RR{a}); err != nil {
		t.Fatalf("sign A: %v", err)
	}
	msg := new(miekgdns.Msg)
	msg.SetQuestion("host.example.com.", miekgdns.TypeA)
	msg.Answer = []miekgdns.RR{a, expired}
	raw, _ := msg.Pack()

	if _, err := VerifyRRsetRRSIGFromResponse(raw, miekgdns.TypeA, rec, key.KeyTag(), "host.example.com.", true); err == nil {
		t.Fatal("an expired (crypto-valid) signature must be rejected by the bound time check")
	}
}
