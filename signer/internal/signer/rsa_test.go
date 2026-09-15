package signer

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
)

// rsaBindKey mints a BIND-style RSA key of the given algorithm and returns
// the DNSKEY with the private half in the BIND multi-field file format.
func rsaBindKey(t *testing.T, alg uint8, flags uint16, rsaBits ...int) (*dns.DNSKEY, string) {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: flags, Protocol: 3, Algorithm: alg}
	bits := 2048
	if len(rsaBits) > 0 {
		bits = rsaBits[0]
	}
	priv, err := k.Generate(bits)
	if err != nil {
		t.Fatal(err)
	}
	return k, k.PrivateKeyString(priv) + "Created: 20251111191453\n"
}

// An RSASHA256/RSASHA512 key this signer mints round-trips through its
// on-disk file, signs, verifies, and is readable by the library's BIND-format
// reader (so dnssec-keygen/ldns tools can read the file too).
func TestRSA_GenerateFormatSignRoundTrip(t *testing.T) {
	for _, name := range []string{"RSASHA256", "RSASHA512"} {
		t.Run(name, func(t *testing.T) {
			dnskey, priv, err := generateDNSSECKey("example.com", name, 256)
			if err != nil {
				t.Fatal(err)
			}
			if got := RSAKeyBits(dnskey); got != rsaGeneratedBits {
				t.Fatalf("generated key is %d bits, want %d", got, rsaGeneratedBits)
			}
			if err := ValidateKeyForImport("example.com", "zsk", dnskey, priv); err != nil {
				t.Fatal(err)
			}

			content, err := formatPrivateKey(dnskey, priv)
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"Private-key-format: v1.3", "Algorithm: ", "Modulus: ", "PublicExponent: ", "PrivateExponent: ", "Prime1: ", "Prime2: ", "Exponent1: ", "Exponent2: ", "Coefficient: ", "Created: "} {
				if !strings.Contains(content, field) {
					t.Fatalf("private file lacks %q:\n%s", field, content)
				}
			}
			if strings.Contains(content, "PrivateKey: ") {
				t.Fatal("an RSA private file must not carry a raw PrivateKey field")
			}
			reparsed, err := ParsePrivateKeyFromFile(content)
			if err != nil {
				t.Fatal(err)
			}
			a, err := x509.ParsePKCS1PrivateKey(priv)
			if err != nil {
				t.Fatal(err)
			}
			b, err := x509.ParsePKCS1PrivateKey(reparsed)
			if err != nil {
				t.Fatal(err)
			}
			if a.N.Cmp(b.N) != 0 || a.D.Cmp(b.D) != 0 || a.E != b.E {
				t.Fatal("the private key did not survive the on-disk round trip")
			}

			rrset := sampleRRset()
			s := &Signer{}
			now := time.Now()
			sig := s.createRRSIG(rrset, dnskey, "example.com.", now.Add(-time.Hour), now.Add(time.Hour))
			if err := s.signRRSIG(sig, rrset, dnskey, priv); err != nil {
				t.Fatal(err)
			}
			if err := sig.Verify(dnskey, rrset); err != nil {
				t.Fatalf("RRSIG by the generated RSA key did not verify: %v", err)
			}

			external, err := dnskey.ReadPrivateKey(strings.NewReader(content), "test")
			if err != nil {
				t.Fatalf("the library's BIND-format reader rejects our file: %v", err)
			}
			sig2 := s.createRRSIG(rrset, dnskey, "example.com.", now.Add(-time.Hour), now.Add(time.Hour))
			if err := sig2.Sign(external.(crypto.Signer), rrset); err != nil {
				t.Fatal(err)
			}
			if err := sig2.Verify(dnskey, rrset); err != nil {
				t.Fatalf("a signature by the externally read key must verify under our DNSKEY: %v", err)
			}
		})
	}
}

// A BIND-format RSA private file imports, and every inconsistency between it
// and the DNSKEY — or inside the file — is caught before use.
func TestRSA_BindFileImportAndMismatch(t *testing.T) {
	k, file := rsaBindKey(t, dns.RSASHA256, 257)
	priv, err := ParsePrivateKeyFromFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeyPairCorrespondence(k, priv); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeyForImport("example.com", "ksk", k, priv); err != nil {
		t.Fatal(err)
	}

	other, _ := rsaBindKey(t, dns.RSASHA256, 257)
	if err := VerifyKeyPairCorrespondence(other, priv); err == nil || !strings.Contains(err.Error(), "does not correspond") {
		t.Fatalf("a private key of another DNSKEY must be rejected, got %v", err)
	}

	fields := parsePrivateKeyFields(file)
	fields["prime1"] = fields["prime2"]
	if _, err := parseBindRSAPrivateKey(fields); err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("a private file whose primes do not match its modulus must be rejected, got %v", err)
	}
	fields = parsePrivateKeyFields(file)
	delete(fields, "modulus")
	if _, err := parseBindRSAPrivateKey(fields); err == nil || !strings.Contains(err.Error(), "modulus") {
		t.Fatalf("a private file missing its modulus must be rejected, got %v", err)
	}
}

// A legacy 512-bit RSASHA256 key remains usable for takeover continuity, while
// anything below that compatibility floor is refused with a size message.
func TestRSA_Legacy512AcceptedAndSmallerRefused(t *testing.T) {
	k, file := rsaBindKey(t, dns.RSASHA256, 256, 512)
	priv, err := ParsePrivateKeyFromFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := RSAKeyBits(k); got != 512 {
		t.Fatalf("legacy key is %d bits, want 512", got)
	}
	if err := ValidateKeyForImport("example.com", "zsk", k, priv); err != nil {
		t.Fatalf("legacy 512-bit takeover key must remain usable: %v", err)
	}

	p, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		t.Fatal(err)
	}
	q, err := rand.Prime(rand.Reader, 128)
	if err != nil {
		t.Fatal(err)
	}
	one := big.NewInt(1)
	n := new(big.Int).Mul(p, q)
	e := big.NewInt(65537)
	phi := new(big.Int).Mul(new(big.Int).Sub(p, one), new(big.Int).Sub(q, one))
	d := new(big.Int).ModInverse(e, phi)
	b64 := func(x *big.Int) string { return base64.StdEncoding.EncodeToString(x.Bytes()) }
	fields := map[string]string{"modulus": b64(n), "publicexponent": b64(e), "privateexponent": b64(d), "prime1": b64(p), "prime2": b64(q)}
	_, err = parseBindRSAPrivateKey(fields)
	if err == nil || !strings.Contains(err.Error(), "at least 512 bits") {
		t.Fatalf("a 256-bit RSA key must be refused by size, got %v", err)
	}
}

// RSASHA1 / RSASHA1-NSEC3-SHA1 material parses and is described, but is never
// accepted for signing.
func TestRSA_SHA1ParsedButRefused(t *testing.T) {
	for _, alg := range []uint8{dns.RSASHA1, dns.RSASHA1NSEC3SHA1} {
		k, file := rsaBindKey(t, alg, 257)
		priv, err := ParsePrivateKeyFromFile(file)
		if err != nil {
			t.Fatalf("%s: the private file must parse: %v", AlgorithmName(alg), err)
		}
		if err := VerifyKeyPairCorrespondence(k, priv); err != nil {
			t.Fatalf("%s: correspondence must be checkable: %v", AlgorithmName(alg), err)
		}
		if got := RSAKeyBits(k); got != 2048 {
			t.Fatalf("%s: bits = %d", AlgorithmName(alg), got)
		}
		err = ValidateKeyForImport("example.com", "ksk", k, priv)
		if err == nil || !strings.Contains(err.Error(), "SHA-1") {
			t.Fatalf("%s must be refused for import with a SHA-1 explanation, got %v", AlgorithmName(alg), err)
		}
		rrset := sampleRRset()
		s := &Signer{}
		sig := s.createRRSIG(rrset, k, "example.com.", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err := s.signRRSIG(sig, rrset, k, priv); err == nil {
			t.Fatalf("%s must never sign", AlgorithmName(alg))
		}
	}
}

// The RFC 3110 public key decoder handles both exponent-length encodings.
func TestRSA_PublicKeyDecode(t *testing.T) {
	modulus := make([]byte, 256)
	modulus[0] = 0x80
	short := append([]byte{3, 1, 0, 1}, modulus...)
	long := append([]byte{0, 0, 3, 1, 0, 1}, modulus...)
	for name, raw := range map[string][]byte{"one-byte length": short, "three-byte length": long} {
		k := &dns.DNSKEY{Algorithm: dns.RSASHA256, PublicKey: base64.StdEncoding.EncodeToString(raw)}
		pub, err := rsaPublicKeyFromDNSKEY(k)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if pub.E != 65537 || pub.N.BitLen() != 2048 {
			t.Fatalf("%s: decoded E=%d bits=%d", name, pub.E, pub.N.BitLen())
		}
	}
	for name, raw := range map[string][]byte{"empty": {}, "zero exponent length": {0, 0, 0, 1}, "truncated": {3, 1, 0}} {
		k := &dns.DNSKEY{Algorithm: dns.RSASHA256, PublicKey: base64.StdEncoding.EncodeToString(raw)}
		if _, err := rsaPublicKeyFromDNSKEY(k); err == nil {
			t.Fatalf("%s: malformed public key must be rejected", name)
		}
	}
}

// Config-level algorithm names include RSA, and a generated RSA key of either
// role is written and reloaded through the normal key transaction.
func TestRSA_KeyGeneratorRoundTrip(t *testing.T) {
	cfg := testConfigWithAlgorithm(t, "RSASHA512")
	kg := NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK("rsa.example")
	if err != nil {
		t.Fatal(err)
	}
	if ksk.Algorithm != "RSASHA512" {
		t.Fatalf("KeyState.Algorithm = %q", ksk.Algorithm)
	}
	dnskey, priv, err := kg.LoadKeyPair("rsa.example", "ksk")
	if err != nil {
		t.Fatal(err)
	}
	if dnskey.KeyTag() != ksk.ID || dnskey.Algorithm != dns.RSASHA512 {
		t.Fatalf("reloaded key %d/%d does not match the generated %d/RSASHA512", dnskey.KeyTag(), dnskey.Algorithm, ksk.ID)
	}
	if err := ValidateKeyForImport("rsa.example", "ksk", dnskey, priv); err != nil {
		t.Fatal(err)
	}
}

// testConfigWithAlgorithm is the shared test config with the given
// configured algorithm.
func testConfigWithAlgorithm(t *testing.T, algorithm string) *config.Config {
	t.Helper()
	cfg := dnssectest.Config(t, t.TempDir())
	cfg.DNSSEC.Algorithm = algorithm
	return cfg
}
