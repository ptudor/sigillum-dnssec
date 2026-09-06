package signer

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
)

// signValidZone builds and signs a small NSEC-signed zone and returns the signed records
// plus the signing keys, for exercising verifySignedZone.
func signValidZone(t *testing.T) (*Signer, []dns.RR, []dns.RR, *signingKeys) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	cfg.DNSSEC.NSECVersion = "nsec"
	keyGen := NewKeyGenerator(cfg)
	if _, err := keyGen.GenerateKSK("example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := keyGen.GenerateZSK("example.com"); err != nil {
		t.Fatal(err)
	}
	kskKey, kskPriv, err := keyGen.LoadKeyPair("example.com", "ksk")
	if err != nil {
		t.Fatal(err)
	}
	zskKey, zskPriv, err := keyGen.LoadKeyPair("example.com", "zsk")
	if err != nil {
		t.Fatal(err)
	}
	keys := &signingKeys{
		dnskeys:      []*dns.DNSKEY{kskKey, zskKey},
		signingKSKs:  []*dns.DNSKEY{kskKey},
		signingKSKPs: [][]byte{kskPriv},
		signingZSKs:  []*dns.DNSKEY{zskKey},
		signingZSKPs: [][]byte{zskPriv},
	}

	mk := func(s string) dns.RR {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return rr
	}
	records := []dns.RR{
		mk("example.com. 3600 IN SOA ns.example.com. admin.example.com. 1 3600 600 86400 3600"),
		mk("example.com. 3600 IN NS ns.example.com."),
		mk("www.example.com. 3600 IN A 192.0.2.1"),
	}
	for _, k := range keys.dnskeys {
		records = append(records, k)
	}
	s := NewSigner(cfg, nil)
	input := append([]dns.RR(nil), records...)
	records = append(records, s.generateNSECChain("example.com", records, 3600)...)

	signed, err := s.signRecordsWithKeys("example.com", records, keys)
	if err != nil {
		t.Fatalf("signRecordsWithKeys: %v", err)
	}
	return s, input, signed, keys
}

// R-001: a valid signed zone passes the self-verification gate.
func TestVerifySignedZone_Valid(t *testing.T) {
	s, input, signed, keys := signValidZone(t)
	if err := s.verifySignedZone("example.com", input, signed, keys); err != nil {
		t.Fatalf("valid signed zone must pass verification, got: %v", err)
	}
}

// R-001 check (1): a corrupted RRSIG signature is caught.
func TestVerifySignedZone_CorruptRRSIG(t *testing.T) {
	s, input, signed, keys := signValidZone(t)
	corrupted := false
	for _, rr := range signed {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeSOA {
			// Flip a byte of the base64 signature so it no longer verifies.
			b := []byte(sig.Signature)
			if b[0] == 'A' {
				b[0] = 'B'
			} else {
				b[0] = 'A'
			}
			sig.Signature = string(b)
			corrupted = true
			break
		}
	}
	if !corrupted {
		t.Fatal("no SOA RRSIG found to corrupt")
	}
	if err := s.verifySignedZone("example.com", input, signed, keys); err == nil {
		t.Fatal("a corrupted RRSIG must fail post-sign verification")
	}
}

// R-001 check (2): an authoritative RRset with no covering RRSIG is caught.
func TestVerifySignedZone_MissingRRSIG(t *testing.T) {
	s, input, signed, keys := signValidZone(t)
	var dropped []dns.RR
	removed := false
	for _, rr := range signed {
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA && !removed {
			removed = true
			continue // drop the A RRSIG, keep the A RRset
		}
		dropped = append(dropped, rr)
	}
	if !removed {
		t.Fatal("no A RRSIG found to drop")
	}
	if err := s.verifySignedZone("example.com", input, dropped, keys); err == nil {
		t.Fatal("an authoritative RRset missing its RRSIG must fail post-sign verification")
	}
}

// R-001 check (3): a broken NSEC chain is caught.
func TestVerifySignedZone_BrokenNSECChain(t *testing.T) {
	s, input, signed, keys := signValidZone(t)
	// Drop the www NSEC and its RRSIG: the apex NSEC still points at www, so the chain
	// no longer closes.
	var broken []dns.RR
	for _, rr := range signed {
		if n, ok := rr.(*dns.NSEC); ok && dns.CanonicalName(n.Hdr.Name) == "www.example.com." {
			continue
		}
		if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeNSEC &&
			dns.CanonicalName(sig.Hdr.Name) == "www.example.com." {
			continue
		}
		broken = append(broken, rr)
	}
	if err := s.verifySignedZone("example.com", input, broken, keys); err == nil {
		t.Fatal("a broken NSEC chain must fail post-sign verification")
	}
}
