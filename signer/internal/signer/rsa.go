package signer

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/miekg/dns"
)

// RSA support (RFC 3110 / RFC 5702), added so zones signed by another tool can
// be taken over with their existing keys and DS records.
//
// In memory an RSA private key travels through the same []byte plumbing as
// every other algorithm, as its PKCS #1 DER encoding. On disk it is the BIND
// multi-field form (Modulus, PublicExponent, PrivateExponent, Prime1, Prime2,
// Exponent1, Exponent2, Coefficient) that dnssec-keygen and ldns-keygen write,
// so a key moves between this signer and those tools without conversion.
//
// RSASHA1 and RSASHA1-NSEC3-SHA1 are RSA too, and their private files parse,
// but the signer refuses to sign with them (see validateLoadedKey): validating
// resolvers no longer treat SHA-1 signatures as secure (RFC 8624 §3.1), so a
// zone signed with them is at best unvalidated and at worst bogus.

const (
	// rsaMinBits is the smallest modulus accepted for an imported or loaded
	// key. crypto/rsa refuses to sign with anything smaller (Go ≥ 1.24), and
	// RFC 6781 §3.4.2 gives no reason to keep such a key in service.
	rsaMinBits = 1024
	// rsaMaxBits bounds the modulus so a DNSKEY RRset and its signatures stay
	// well inside one response; it is also the largest size ldns/BIND mint.
	rsaMaxBits = 4096
	// rsaGeneratedBits is the modulus of RSA keys this signer mints itself —
	// only ever as the successor of an RSA key at rollover, or when the
	// operator configured an RSA algorithm outright.
	rsaGeneratedBits = 2048
)

// isRSA reports whether alg is one of the RSA algorithms this signer signs
// with. The SHA-1 variants are deliberately excluded.
func isRSA(alg uint8) bool {
	return alg == dns.RSASHA256 || alg == dns.RSASHA512
}

// isSHA1RSA reports whether alg is an RSA/SHA-1 algorithm: parseable, never
// signed with.
func isSHA1RSA(alg uint8) bool {
	return alg == dns.RSASHA1 || alg == dns.RSASHA1NSEC3SHA1
}

// rsaPublicKeyFromDNSKEY decodes the RFC 3110 §2 public key field of an RSA
// DNSKEY: a one-byte exponent length (or a zero byte followed by a two-byte
// length), the exponent, then the modulus.
func rsaPublicKeyFromDNSKEY(dnskey *dns.DNSKEY) (*rsa.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(dnskey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decoding DNSKEY public key: %w", err)
	}
	if len(raw) < 3 {
		return nil, fmt.Errorf("RSA DNSKEY public key is too short (%d bytes)", len(raw))
	}
	expLen, off := int(raw[0]), 1
	if expLen == 0 {
		expLen, off = int(raw[1])<<8|int(raw[2]), 3
	}
	if expLen == 0 || len(raw) < off+expLen+1 {
		return nil, fmt.Errorf("RSA DNSKEY public key has a malformed exponent length")
	}
	e := new(big.Int).SetBytes(raw[off : off+expLen])
	if e.BitLen() > 31 {
		return nil, fmt.Errorf("RSA DNSKEY public exponent is too large (%d bits)", e.BitLen())
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(raw[off+expLen:]), E: int(e.Int64())}, nil
}

// parseBindRSAPrivateKey builds an RSA private key from the BIND private-key
// fields (already split into lowercase name → value) and returns it as PKCS #1
// DER. Only the modulus, both exponents and the two primes are read; the CRT
// values are recomputed, and the key must be internally consistent (the
// primes multiply to the modulus and the exponents invert each other) before
// it is accepted.
func parseBindRSAPrivateKey(fields map[string]string) ([]byte, error) {
	get := func(name string) (*big.Int, error) {
		v, ok := fields[name]
		if !ok {
			return nil, fmt.Errorf("no %s field in RSA private key file", name)
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("decoding %s: %w", name, err)
		}
		if len(b) == 0 {
			return nil, fmt.Errorf("%s field is empty", name)
		}
		return new(big.Int).SetBytes(b), nil
	}
	n, err := get("modulus")
	if err != nil {
		return nil, err
	}
	e, err := get("publicexponent")
	if err != nil {
		return nil, err
	}
	d, err := get("privateexponent")
	if err != nil {
		return nil, err
	}
	p, err := get("prime1")
	if err != nil {
		return nil, err
	}
	q, err := get("prime2")
	if err != nil {
		return nil, err
	}
	if err := checkRSABits(n.BitLen()); err != nil {
		return nil, err
	}
	if e.BitLen() > 31 {
		return nil, fmt.Errorf("RSA public exponent is too large (%d bits)", e.BitLen())
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	key.Precompute()
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("RSA private key is inconsistent: %w", err)
	}
	return x509.MarshalPKCS1PrivateKey(key), nil
}

// checkRSABits enforces the accepted modulus range.
func checkRSABits(bits int) error {
	if bits < rsaMinBits {
		return fmt.Errorf("RSA key is %d bits; at least %d bits are required (smaller keys are refused by current cryptographic libraries and offer no security)", bits, rsaMinBits)
	}
	if bits > rsaMaxBits {
		return fmt.Errorf("RSA key is %d bits; at most %d bits are supported", bits, rsaMaxBits)
	}
	return nil
}

// rsaPrivateKeyFromBytes decodes the in-memory PKCS #1 DER form.
func rsaPrivateKeyFromBytes(privateKey []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS1PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA private key: %w", err)
	}
	if err := checkRSABits(key.N.BitLen()); err != nil {
		return nil, err
	}
	return key, nil
}

// verifyRSACorrespondence checks that the private key's modulus and exponent
// are exactly the DNSKEY's.
func verifyRSACorrespondence(dnskey *dns.DNSKEY, privateKey []byte) error {
	priv, err := rsaPrivateKeyFromBytes(privateKey)
	if err != nil {
		return err
	}
	pub, err := rsaPublicKeyFromDNSKEY(dnskey)
	if err != nil {
		return err
	}
	if pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
		return fmt.Errorf("RSA private key does not correspond to the DNSKEY public key (key tag %d)", dnskey.KeyTag())
	}
	return nil
}

// RSAKeyBits returns the modulus size of an RSA DNSKEY, or 0 for any other
// algorithm or an undecodable key.
func RSAKeyBits(dnskey *dns.DNSKEY) int {
	if dnskey == nil || (!isRSA(dnskey.Algorithm) && !isSHA1RSA(dnskey.Algorithm)) {
		return 0
	}
	pub, err := rsaPublicKeyFromDNSKEY(dnskey)
	if err != nil {
		return 0
	}
	return pub.N.BitLen()
}

// generateRSAKey mints an RSA key pair of rsaGeneratedBits for dnskey (whose
// Algorithm must already be set), fills in its public key field and returns
// the private half in the in-memory form.
func generateRSAKey(dnskey *dns.DNSKEY) ([]byte, error) {
	priv, err := dnskey.Generate(rsaGeneratedBits)
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", AlgorithmName(dnskey.Algorithm), err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("generating %s key: unexpected private key type %T", AlgorithmName(dnskey.Algorithm), priv)
	}
	return x509.MarshalPKCS1PrivateKey(rsaKey), nil
}

// formatRSAPrivateKey writes the BIND multi-field private key file for an RSA
// key (the format dnssec-keygen and ldns-keygen read), with the same trailing
// Created line the other algorithms carry.
func formatRSAPrivateKey(dnskey *dns.DNSKEY, privateKey []byte, created string) (string, error) {
	priv, err := rsaPrivateKeyFromBytes(privateKey)
	if err != nil {
		return "", err
	}
	return dnskey.PrivateKeyString(priv) + "Created: " + created + "\n", nil
}
