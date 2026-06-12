package validator

import (
	"crypto"
	"testing"
	"time"

	miekgdns "github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// buildSignedNSECResponse builds a DNS response whose authority section contains an
// NSEC RRset signed by a freshly generated ECDSA P-256 ZSK. The NSEC that is *served*
// in the response carries nextServed, while the signature is computed over an NSEC
// carrying nextSigned. When nextServed == nextSigned the signature is genuine; when
// they differ the served record is effectively forged and must fail verification.
//
// It returns the packed wire response plus the validator-typed key / NSEC / RRSIG that
// a real response parse would have produced from the served record.
func buildSignedNSECResponse(t *testing.T, owner, nextSigned, nextServed string) (raw []byte, key dnspkg.DNSKEYRecord, nsec dnspkg.NSECRecord, rrsig dnspkg.RRSIGRecord) {
	t.Helper()

	const zone = "example.com."
	const ttl = 300

	dnskey := &miekgdns.DNSKEY{
		Hdr:       miekgdns.RR_Header{Name: zone, Rrtype: miekgdns.TypeDNSKEY, Class: miekgdns.ClassINET, Ttl: ttl},
		Flags:     256,
		Protocol:  3,
		Algorithm: miekgdns.ECDSAP256SHA256,
	}
	priv, err := dnskey.Generate(256)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatal("generated private key is not a crypto.Signer")
	}

	bitmap := []uint16{miekgdns.TypeA, miekgdns.TypeRRSIG, miekgdns.TypeNSEC}

	nsecSigned := &miekgdns.NSEC{
		Hdr:        miekgdns.RR_Header{Name: owner, Rrtype: miekgdns.TypeNSEC, Class: miekgdns.ClassINET, Ttl: ttl},
		NextDomain: nextSigned,
		TypeBitMap: bitmap,
	}

	inception := time.Now().Add(-1 * time.Hour)
	expiration := time.Now().Add(24 * time.Hour)

	sig := &miekgdns.RRSIG{
		Hdr:         miekgdns.RR_Header{Name: owner, Rrtype: miekgdns.TypeRRSIG, Class: miekgdns.ClassINET, Ttl: ttl},
		TypeCovered: miekgdns.TypeNSEC,
		Algorithm:   miekgdns.ECDSAP256SHA256,
		Labels:      uint8(miekgdns.CountLabel(owner)),
		OrigTtl:     ttl,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      dnskey.KeyTag(),
		SignerName:  zone,
	}
	if err := sig.Sign(signer, []miekgdns.RR{nsecSigned}); err != nil {
		t.Fatalf("sign NSEC RRset: %v", err)
	}

	nsecServed := &miekgdns.NSEC{
		Hdr:        miekgdns.RR_Header{Name: owner, Rrtype: miekgdns.TypeNSEC, Class: miekgdns.ClassINET, Ttl: ttl},
		NextDomain: nextServed,
		TypeBitMap: bitmap,
	}

	msg := new(miekgdns.Msg)
	msg.SetQuestion("nonexistent.example.com.", miekgdns.TypeA)
	msg.Rcode = miekgdns.RcodeNameError
	msg.Ns = []miekgdns.RR{nsecServed, sig}
	raw, err = msg.Pack()
	if err != nil {
		t.Fatalf("pack response: %v", err)
	}

	key = dnspkg.DNSKEYRecord{
		Flags:     dnskey.Flags,
		Protocol:  dnskey.Protocol,
		Algorithm: dnskey.Algorithm,
		PublicKey: dnskey.PublicKey,
		KeyTag:    dnskey.KeyTag(),
		IsZSK:     true,
	}
	nsec = dnspkg.NSECRecord{
		Owner:      owner,
		NextDomain: nextServed,
		TypeBitmap: []string{"A", "RRSIG", "NSEC"},
	}
	rrsig = dnspkg.RRSIGRecord{
		TypeCovered: 47,
		Algorithm:   dnskey.Algorithm,
		Labels:      uint8(miekgdns.CountLabel(owner)),
		OriginalTTL: ttl,
		Expiration:  expiration,
		Inception:   inception,
		KeyTag:      dnskey.KeyTag(),
		SignerName:  zone,
		Signature:   sig.Signature,
		IsValid:     true,
	}
	return raw, key, nsec, rrsig
}

func TestVerifyDenialRRSIGFromResponse_ValidNSEC(t *testing.T) {
	raw, key, _, _ := buildSignedNSECResponse(t, "example.com.", "zzz.example.com.", "zzz.example.com.")

	n, err := VerifyDenialRRSIGFromResponse(raw, 47, []dnspkg.DNSKEYRecord{key})
	if err != nil {
		t.Fatalf("expected a genuine NSEC RRSIG to verify, got error: %v", err)
	}
	if n != 1 {
		t.Fatalf("verified RRset count = %d, want 1", n)
	}
}

func TestVerifyDenialRRSIGFromResponse_TamperedNSEC(t *testing.T) {
	// Signed over next=zzz, served with next=yyy: the signature cannot cover the
	// served record, so verification must fail closed.
	raw, key, _, _ := buildSignedNSECResponse(t, "example.com.", "zzz.example.com.", "yyy.example.com.")

	if _, err := VerifyDenialRRSIGFromResponse(raw, 47, []dnspkg.DNSKEYRecord{key}); err == nil {
		t.Fatal("expected cryptographic verification to fail for a tampered NSEC, got nil error")
	}
}

func TestVerifyDenialRRSIGFromResponse_NoMatchingKey(t *testing.T) {
	raw, _, _, _ := buildSignedNSECResponse(t, "example.com.", "zzz.example.com.", "zzz.example.com.")

	// A key whose tag does not match the RRSIG: there is no signer to verify against.
	otherKey := dnspkg.DNSKEYRecord{Flags: 256, Protocol: 3, Algorithm: 13, PublicKey: "AAAAAAAA", KeyTag: 1}
	if _, err := VerifyDenialRRSIGFromResponse(raw, 47, []dnspkg.DNSKEYRecord{otherKey}); err == nil {
		t.Fatal("expected error when no DNSKEY matches the NSEC RRSIG key tag")
	}
}

func TestVerifyDenialRRSIGFromResponse_EmptyAndMalformed(t *testing.T) {
	key := dnspkg.DNSKEYRecord{Flags: 256, Protocol: 3, Algorithm: 13, PublicKey: "AAAAAAAA", KeyTag: 1}

	if _, err := VerifyDenialRRSIGFromResponse(nil, 47, []dnspkg.DNSKEYRecord{key}); err == nil {
		t.Fatal("expected error for empty raw response")
	}
	if _, err := VerifyDenialRRSIGFromResponse([]byte{0x00, 0x01, 0x02}, 47, []dnspkg.DNSKEYRecord{key}); err == nil {
		t.Fatal("expected error for malformed raw response")
	}
}

func TestVerifyNSECDenialWithRRSIG_VerifiesSignature(t *testing.T) {
	raw, key, nsec, rrsig := buildSignedNSECResponse(t, "example.com.", "zzz.example.com.", "zzz.example.com.")

	proof := VerifyNSECDenialWithRRSIG("nonexistent.example.com.", miekgdns.TypeA,
		[]dnspkg.NSECRecord{nsec}, []dnspkg.RRSIGRecord{rrsig}, []dnspkg.DNSKEYRecord{key}, raw, 3)

	if !proof.Verified {
		t.Fatalf("expected a genuine denial proof to verify, got error: %q", proof.Error)
	}
}

func TestVerifyNSECDenialWithRRSIG_RejectsForgedSignature(t *testing.T) {
	// The served NSEC (next=yyy) still covers the qname for the range proof, but its
	// signature is over a different record (next=zzz). The old code reported this as
	// verified on key-tag + timestamp alone; it must now be rejected.
	raw, key, nsec, rrsig := buildSignedNSECResponse(t, "example.com.", "zzz.example.com.", "yyy.example.com.")

	proof := VerifyNSECDenialWithRRSIG("nonexistent.example.com.", miekgdns.TypeA,
		[]dnspkg.NSECRecord{nsec}, []dnspkg.RRSIGRecord{rrsig}, []dnspkg.DNSKEYRecord{key}, raw, 3)

	if proof.Verified {
		t.Fatal("forged NSEC signature was incorrectly reported as cryptographically verified")
	}
	if proof.Error == "" {
		t.Fatal("expected an error explaining the verification failure")
	}
}

func TestVerifyNSECDenialWithRRSIG_RequiresRawResponse(t *testing.T) {
	_, key, nsec, rrsig := buildSignedNSECResponse(t, "example.com.", "zzz.example.com.", "zzz.example.com.")

	// No raw response means the signature cannot be checked; the proof must not verify.
	proof := VerifyNSECDenialWithRRSIG("nonexistent.example.com.", miekgdns.TypeA,
		[]dnspkg.NSECRecord{nsec}, []dnspkg.RRSIGRecord{rrsig}, []dnspkg.DNSKEYRecord{key}, nil, 3)

	if proof.Verified {
		t.Fatal("denial proof reported verified without a raw response to check the signature")
	}
	if proof.Error == "" {
		t.Fatal("expected an error explaining the missing raw response")
	}
}

func TestVerifyNSEC3DenialWithRRSIG_RequiresRawResponse(t *testing.T) {
	nsec3 := dnspkg.NSEC3Record{
		HashedOwner: "ABCDEF",
		NextHashed:  "XYZ123",
		Algorithm:   1,
		TypeBitmap:  []string{"A"},
	}
	rrsig := dnspkg.RRSIGRecord{
		TypeCovered: 50,
		KeyTag:      123,
		SignerName:  "example.com.",
		Inception:   time.Now().Add(-time.Hour),
		Expiration:  time.Now().Add(time.Hour),
		IsValid:     true,
	}
	key := dnspkg.DNSKEYRecord{Flags: 256, Protocol: 3, Algorithm: 13, KeyTag: 123, PublicKey: "AAAAAAAA", IsZSK: true}

	// Fail closed: with no raw response, NSEC3 denial cannot be cryptographically proven.
	proof := VerifyNSEC3DenialWithRRSIG("x.example.com.", miekgdns.TypeA,
		[]dnspkg.NSEC3Record{nsec3}, []dnspkg.RRSIGRecord{rrsig}, []dnspkg.DNSKEYRecord{key}, "example.com.", nil, 3)

	if proof.Verified {
		t.Fatal("NSEC3 denial reported verified without a raw response to check the signature")
	}
	if proof.Error == "" {
		t.Fatal("expected an error explaining the missing raw response")
	}
}
