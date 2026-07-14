package signer

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
)

// --- Item 12: post-sign verify gate must accept mixed-case duplicate owner spellings ---

// signMixedCaseZone mirrors signValidZone (post_sign_verify_test.go) but spells
// one RRset's owner with divergent letter case: `www` and `WWW` A records.
// DNSSEC canonical form (RFC 4034 §6.2) lowercases owner names, so these are
// one RRset on the wire and the signature over them is valid.
func signMixedCaseZone(t *testing.T) (*Signer, []dns.RR, *signingKeys) {
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
		mk("WWW.example.com. 3600 IN A 192.0.2.2"),
	}
	for _, k := range keys.dnskeys {
		records = append(records, k)
	}
	s := NewSigner(cfg, nil)
	records = append(records, s.generateNSECChain("example.com", records, 3600)...)

	signed, err := s.signRecordsWithKeys("example.com", records, keys)
	if err != nil {
		t.Fatalf("signRecordsWithKeys: %v", err)
	}
	return s, signed, keys
}

// A zone spelling one owner in different letter case within an RRset signs
// fine and validates on the wire; the verify gate must not reject it
// (pre-fix, miekg's case-sensitive IsRRset made sig.Verify return ErrRRset).
// The gate must not go blind either: a genuinely corrupt RRSIG over the
// mixed-case RRset is still rejected.
func TestVerifySignedZone_MixedCaseOwnerRRset(t *testing.T) {
	t.Run("mixed-case owner spellings pass verification", func(t *testing.T) {
		s, signed, keys := signMixedCaseZone(t)
		if err := s.verifySignedZone("example.com", signed, keys); err != nil {
			t.Fatalf("a signed zone with mixed-case owner spellings must pass verification, got: %v", err)
		}
		// Verification works on copies: the records that will be written keep
		// their original spelling.
		foundUpper := false
		for _, rr := range signed {
			if rr.Header().Rrtype == dns.TypeA && strings.HasPrefix(rr.Header().Name, "WWW.") {
				foundUpper = true
				break
			}
		}
		if !foundUpper {
			t.Error("verification must not mutate the records to be written (WWW. spelling lost)")
		}
	})

	t.Run("corrupt RRSIG over the mixed-case RRset is still rejected", func(t *testing.T) {
		s, signed, keys := signMixedCaseZone(t)
		corrupted := false
		for _, rr := range signed {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA {
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
			t.Fatal("no A RRSIG found to corrupt")
		}
		if err := s.verifySignedZone("example.com", signed, keys); err == nil {
			t.Fatal("a corrupt RRSIG over a mixed-case RRset must still fail verification")
		}
	})
}
