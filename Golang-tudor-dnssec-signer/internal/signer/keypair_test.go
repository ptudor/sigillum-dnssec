package signer

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func ed25519DNSKEY(pub ed25519.PublicKey) *dns.DNSKEY {
	return &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
}

func sampleRRset() []dns.RR {
	return []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"hello"},
	}}
}

// R-010: a 32-byte-seed ED25519 private key (the BIND/ldns/RFC 8080 form) must sign
// without panicking, and the resulting RRSIG must verify. The 64-byte form must too.
func TestSignRRSIG_ED25519SeedAndFull(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dnskey := ed25519DNSKEY(pub)
	rrset := sampleRRset()
	s := &Signer{}
	inception := time.Now().Add(-time.Hour)
	expiration := time.Now().Add(24 * time.Hour)

	// 32-byte seed (imported BIND key).
	rrsig := s.createRRSIG(rrset, dnskey, "example.com.", inception, expiration)
	if err := s.signRRSIG(rrsig, rrset, dnskey, priv.Seed()); err != nil {
		t.Fatalf("signRRSIG with 32-byte seed: %v", err)
	}
	if err := rrsig.Verify(dnskey, rrset); err != nil {
		t.Fatalf("RRSIG from 32-byte seed did not verify: %v", err)
	}

	// 64-byte expanded key (internally generated).
	rrsig2 := s.createRRSIG(rrset, dnskey, "example.com.", inception, expiration)
	if err := s.signRRSIG(rrsig2, rrset, dnskey, priv); err != nil {
		t.Fatalf("signRRSIG with 64-byte key: %v", err)
	}
	if err := rrsig2.Verify(dnskey, rrset); err != nil {
		t.Fatalf("RRSIG from 64-byte key did not verify: %v", err)
	}
}

// R-010: a wrong-length ED25519 key must return an error, never panic.
func TestSignRRSIG_GarbageLengthErrorsNoPanic(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	dnskey := ed25519DNSKEY(pub)
	rrset := sampleRRset()
	s := &Signer{}
	rrsig := s.createRRSIG(rrset, dnskey, "example.com.", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err := s.signRRSIG(rrsig, rrset, dnskey, make([]byte, 10)); err == nil {
		t.Fatal("expected an error for a 10-byte ED25519 key, got nil (would previously panic)")
	}
}

// R-009 / R-010: the pub/priv correspondence check accepts every generated/imported key
// form and rejects a mismatched pair.
func TestVerifyKeyPairCorrespondence(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dnskey := ed25519DNSKEY(pub)

	if err := VerifyKeyPairCorrespondence(dnskey, priv.Seed()); err != nil {
		t.Fatalf("32-byte seed should correspond: %v", err)
	}
	if err := VerifyKeyPairCorrespondence(dnskey, priv); err != nil {
		t.Fatalf("64-byte key should correspond: %v", err)
	}

	// A different key's private half must be rejected (the R-009 mismatch case).
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyKeyPairCorrespondence(dnskey, priv2); err == nil {
		t.Fatal("mismatched ED25519 private key must be rejected")
	}

	// ECDSA P-256 correspondence.
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := make([]byte, 64)
	ec.PublicKey.X.FillBytes(pubBytes[:32])
	ec.PublicKey.Y.FillBytes(pubBytes[32:])
	dBytes := make([]byte, 32)
	ec.D.FillBytes(dBytes)
	ecKey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
		PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
	}
	if err := VerifyKeyPairCorrespondence(ecKey, dBytes); err != nil {
		t.Fatalf("matching ECDSA pair should correspond: %v", err)
	}
	if err := VerifyKeyPairCorrespondence(ecKey, make([]byte, 32)); err == nil {
		t.Fatal("a zero ECDSA scalar must not correspond to the real public key")
	}
}
