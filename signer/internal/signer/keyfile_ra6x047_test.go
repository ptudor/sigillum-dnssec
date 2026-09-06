package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
)

// A generated ED25519 private file is readable by the BIND-format reader of
// the DNS library (an independent implementation of the file format), signs
// the same RRset to a signature our DNSKEY verifies, and keeps the DNSKEY/DS
// bytes unchanged; a legacy 64-byte file still loads.
func TestED25519PrivateFile_BINDCompatibleSeed(t *testing.T) {
	cfg := dnssectest.Config(t, t.TempDir())
	kg := NewKeyGenerator(cfg)
	if _, err := kg.GenerateKSK("example.com"); err != nil {
		t.Fatal(err)
	}
	base := kg.liveBase("example.com", "ksk")
	dnskey, ourPriv, err := kg.LoadKeyPair("example.com", "ksk")
	if err != nil {
		t.Fatal(err)
	}
	if len(ourPriv) != ed25519.SeedSize {
		t.Fatalf("the private file must carry the 32-byte seed, got %d bytes", len(ourPriv))
	}

	content, err := os.ReadFile(base + ".private")
	if err != nil {
		t.Fatal(err)
	}
	// Independent reader: miekg/dns's BIND private-key parser.
	external, err := dnskey.ReadPrivateKey(strings.NewReader(string(content)), base+".private")
	if err != nil {
		t.Fatalf("the BIND-format reader must accept the generated file: %v", err)
	}
	extKey, ok := external.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("unexpected key type %T", external)
	}
	if !extKey.Public().(ed25519.PublicKey).Equal(ed25519.NewKeyFromSeed(ourPriv).Public()) {
		t.Fatal("the external reader must derive the same public key")
	}

	// Sign with the externally read key, verify with our DNSKEY (same identity).
	rrset := []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"x"}}}
	sig := &dns.RRSIG{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 60},
		TypeCovered: dns.TypeTXT, Algorithm: dns.ED25519, Labels: 2, OrigTtl: 60,
		Expiration: uint32(time.Now().Add(time.Hour).Unix()), Inception: uint32(time.Now().Add(-time.Hour).Unix()),
		KeyTag: dnskey.KeyTag(), SignerName: "example.com."}
	if err := sig.Sign(extKey, rrset); err != nil {
		t.Fatal(err)
	}
	if err := sig.Verify(dnskey, rrset); err != nil {
		t.Fatalf("a signature by the externally read key must verify under our DNSKEY: %v", err)
	}

	// A legacy 64-byte file written by earlier versions still loads and yields
	// the same DNSKEY and DS.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "legacy.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: 257, Protocol: 3, Algorithm: dns.ED25519, PublicKey: base64.StdEncoding.EncodeToString(pub)}
	legacyBase := filepath.Join(cfg.KeysDir(), "legacy.example.ksk")
	if err := os.WriteFile(legacyBase+".key", []byte(legacy.String()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	legacyFile := "Private-key-format: v1.3\nAlgorithm: 15 (ED25519)\nPrivateKey: " + base64.StdEncoding.EncodeToString(priv) + "\n"
	if err := os.WriteFile(legacyBase+".private", []byte(legacyFile), 0600); err != nil {
		t.Fatal(err)
	}
	got, gotPriv, err := kg.LoadKeyPair("legacy.example", "ksk")
	if err != nil {
		t.Fatalf("a legacy 64-byte private file must still load: %v", err)
	}
	if got.PublicKey != legacy.PublicKey || got.ToDS(dns.SHA256).Digest != legacy.ToDS(dns.SHA256).Digest || len(gotPriv) != ed25519.PrivateKeySize {
		t.Fatal("legacy key identity must be unchanged")
	}
	// Re-serializing it (e.g. a staged copy) converts to the seed without
	// changing the identity; a corrupted expanded key is left untouched.
	if seed := privateBytesOf(formatPrivateKey(legacy, priv)); len(seed) != ed25519.SeedSize {
		t.Fatalf("re-serialized legacy key must be the seed, got %d bytes", len(seed))
	}
	corrupt := append([]byte(nil), priv...)
	corrupt[0] ^= 1
	if raw := privateBytesOf(formatPrivateKey(legacy, corrupt)); len(raw) != ed25519.PrivateKeySize {
		t.Fatal("an inconsistent expanded key must not be silently rewritten as a seed")
	}
}

// privateBytesOf extracts the PrivateKey bytes from a formatted file.
func privateBytesOf(content string) []byte {
	b, err := ParsePrivateKeyFromFile(content)
	if err != nil {
		return nil
	}
	return b
}
