package signer

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// --- fixtures ---------------------------------------------------------------

// semZone is a signable zone whose unsigned file the test controls.
type semZone struct {
	cfg      *config.Config
	state    *statepkg.State
	signer   *Signer
	domain   string
	zonePath string
}

func newSemZone(t *testing.T, mode string, zoneText string) *semZone {
	t.Helper()
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	cfg.DNSSEC.NSECVersion = mode
	domain := "example.com"
	zonePath := filepath.Join(dataDir, "example.com.zone")
	if err := os.WriteFile(zonePath, []byte(zoneText), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}
	for _, d := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	kg := NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	st := statepkg.NewState(cfg.StatePath())
	st.SetZone(domain, &statepkg.ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})
	return &semZone{cfg: cfg, state: st, signer: NewSigner(cfg, st), domain: domain, zonePath: zonePath}
}

func (z *semZone) outputPath() string { return z.signer.OutputPath(z.domain) }

func (z *semZone) setZone(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(z.zonePath, []byte(text), 0644); err != nil {
		t.Fatal(err)
	}
	// Ensure the mtime moves so change detection is not a factor.
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(z.zonePath, future, future)
}

const baseZone = `$ORIGIN example.com.
$TTL 3600
@	IN	SOA	ns1.example.com. admin.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.example.com.
ns1	IN	A	192.0.2.1
`

// parseSigned reads the signed output back through miekg's zone parser.
func parseSigned(t *testing.T, path, domain string) []dns.RR {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading signed zone: %v", err)
	}
	var out []dns.RR
	zp := dns.NewZoneParser(strings.NewReader(string(data)), dns.Fqdn(domain), path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		out = append(out, rr)
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("signed zone does not parse: %v", err)
	}
	return out
}

// wireKey identifies an owner by its packed wire form — an identity computed
// independently of the signer's canonicalName.
func wireKey(t *testing.T, name string) string {
	t.Helper()
	buf := make([]byte, 255)
	off, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		t.Fatalf("packing %q: %v", name, err)
	}
	// Lowercase the label octets as RFC 4034 §6.2 canonical form does.
	return strings.ToLower(string(buf[:off]))
}

type wireRRset struct {
	name   string
	rrtype uint16
}

// independentVerify groups the served records by wire owner (as an
// authoritative server does), and requires every non-DNSSEC RRset in the zone
// to be exactly one semantic RRset with a verifying RRSIG under a published
// DNSKEY, using wire-normalized copies. It returns the RRset map for further
// assertions.
func independentVerify(t *testing.T, records []dns.RR, expectUnsigned map[wireRRset]bool) map[wireRRset][]dns.RR {
	t.Helper()
	sets := map[wireRRset][]dns.RR{}
	sigs := map[wireRRset][]*dns.RRSIG{}
	var keys []*dns.DNSKEY
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			k := wireRRset{wireKey(t, sig.Hdr.Name), sig.TypeCovered}
			sigs[k] = append(sigs[k], sig)
			continue
		}
		if dk, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, dk)
		}
		k := wireRRset{wireKey(t, rr.Header().Name), rr.Header().Rrtype}
		sets[k] = append(sets[k], rr)
	}
	for k, set := range sets {
		if expectUnsigned[k] {
			if len(sigs[k]) != 0 {
				t.Fatalf("RRset %v must not be signed", k)
			}
			continue
		}
		if len(sigs[k]) == 0 {
			t.Fatalf("RRset %s type %s has no RRSIG", set[0].Header().Name, dns.TypeToString[k.rrtype])
		}
		// Normalize every owner spelling to one canonical presentation so
		// miekg's Verify sees one RRset, as a resolver would on the wire.
		norm := make([]dns.RR, len(set))
		for i, rr := range set {
			cp := dns.Copy(rr)
			cp.Header().Name = dns.CanonicalName(unescapeName(t, rr.Header().Name))
			norm[i] = cp
		}
		verified := false
		for _, sig := range sigs[k] {
			for _, dk := range keys {
				if dk.KeyTag() != sig.KeyTag || dk.Algorithm != sig.Algorithm {
					continue
				}
				if err := sig.Verify(dk, norm); err == nil {
					verified = true
				}
			}
		}
		if !verified {
			t.Fatalf("no RRSIG over the complete semantic RRset %s %s verifies (%d records)", set[0].Header().Name, dns.TypeToString[k.rrtype], len(set))
		}
	}
	return sets
}

// unescapeName rewrites a presentation name into the spelling miekg produces
// from wire form, so equal wire names compare equal after CanonicalName.
func unescapeName(t *testing.T, name string) string {
	t.Helper()
	buf := make([]byte, 255)
	off, err := dns.PackDomainName(name, buf, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	s, _, err := dns.UnpackDomainName(buf[:off], 0)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// --- RA6X-028: canonical owner identity ---------------------------------------

func TestSignZone_EquivalentEscapedOwnersFormOneRRset(t *testing.T) {
	for _, mode := range []string{"nsec", "nsec3"} {
		t.Run(mode, func(t *testing.T) {
			z := newSemZone(t, mode, baseZone+`www	IN	A	192.0.2.10
\119ww	IN	A	192.0.2.11
WWW	IN	A	192.0.2.12
\042	IN	TXT	"wildcard"
*.wild	IN	A	192.0.2.20
a\.b	IN	A	192.0.2.30
a.b	IN	A	192.0.2.31
x\000y	IN	A	192.0.2.40
xy	IN	A	192.0.2.41
Child	IN	NS	ns.child.example.com.
ns.\099hild	IN	A	192.0.2.50
`)
			if err := z.signer.SignZone(z.domain); err != nil {
				t.Fatalf("SignZone: %v", err)
			}
			records := parseSigned(t, z.outputPath(), z.domain)
			unsigned := map[wireRRset]bool{
				{wireKey(t, "child.example.com."), dns.TypeNS}:   true,
				{wireKey(t, "ns.child.example.com."), dns.TypeA}: true,
			}
			sets := independentVerify(t, records, unsigned)

			www := sets[wireRRset{wireKey(t, "www.example.com."), dns.TypeA}]
			if len(www) != 3 {
				t.Fatalf("www A RRset must merge all three spellings, got %d records", len(www))
			}
			if len(sets[wireRRset{wireKey(t, "a\\.b.example.com."), dns.TypeA}]) != 1 || len(sets[wireRRset{wireKey(t, "a.b.example.com."), dns.TypeA}]) != 1 {
				t.Fatal("an escaped dot and a real dot are different names and must not merge")
			}
			if len(sets[wireRRset{wireKey(t, "x\\000y.example.com."), dns.TypeA}]) != 1 || len(sets[wireRRset{wireKey(t, "xy.example.com."), dns.TypeA}]) != 1 {
				t.Fatal("distinct binary labels must not merge")
			}
			if _, ok := sets[wireRRset{wireKey(t, "ns.child.example.com."), dns.TypeA}]; !ok {
				t.Fatal("glue below the escaped-spelling delegation must be preserved (unsigned)")
			}

			// Wildcard RRSIGs carry the label count without the wildcard label.
			for _, rr := range records {
				if sig, ok := rr.(*dns.RRSIG); ok {
					switch wireKey(t, sig.Hdr.Name) {
					case wireKey(t, "*.example.com."):
						if sig.Labels != 2 {
							t.Fatalf("escaped-asterisk wildcard RRSIG labels = %d, want 2", sig.Labels)
						}
					case wireKey(t, "*.wild.example.com."):
						if sig.Labels != 3 {
							t.Fatalf("wildcard RRSIG labels = %d, want 3", sig.Labels)
						}
					}
				}
			}

			// Exactly one denial owner per semantic name.
			if mode == "nsec" {
				count := 0
				for _, rr := range records {
					if n, ok := rr.(*dns.NSEC); ok && wireKey(t, n.Hdr.Name) == wireKey(t, "www.example.com.") {
						count++
						if !hasType(n.TypeBitMap, dns.TypeA) {
							t.Fatal("www NSEC bitmap must list A")
						}
					}
				}
				if count != 1 {
					t.Fatalf("expected one NSEC for www, got %d", count)
				}
			} else {
				hash := strings.ToUpper(dns.HashName("www.example.com.", dns.SHA1, uint16(z.cfg.DNSSEC.NSEC3Iterations), z.cfg.DNSSEC.NSEC3Salt))
				count := 0
				for _, rr := range records {
					if n, ok := rr.(*dns.NSEC3); ok && strings.ToUpper(dns.SplitDomainName(n.Hdr.Name)[0]) == hash {
						count++
					}
				}
				if count != 1 {
					t.Fatalf("expected one NSEC3 for www, got %d", count)
				}
			}
		})
	}
}

func hasType(bitmap []uint16, t uint16) bool {
	for _, b := range bitmap {
		if b == t {
			return true
		}
	}
	return false
}

func TestCanonicalName(t *testing.T) {
	cases := map[string]string{
		"WWW.Example.COM.":     "www.example.com.",
		`\119ww.example.com.`:  "www.example.com.",
		`\065.example.com.`:    "a.example.com.",
		`a\.b.example.com.`:    `a\.b.example.com.`,
		`x\000y.example.com.`:  `x\000y.example.com.`,
		`sp\ ace.example.com.`: `sp\032ace.example.com.`,
		`back\\slash.example.`: `back\\slash.example.`,
		"\\042.example.com.":   "*.example.com.",
		".":                    ".",
		"example.com":          "example.com.",
	}
	for in, want := range cases {
		if got := canonicalName(in); got != want {
			t.Errorf("canonicalName(%q) = %q, want %q", in, got, want)
		}
	}
	if canonicalName(`a\.b.example.com.`) == canonicalName("a.b.example.com.") {
		t.Fatal("escaped dot must not equal a label separator")
	}
}

// --- RA6X-029: semantic owner/type constraints -------------------------------

func TestValidateZone_RejectsInvalidOwnerTypeCombinations(t *testing.T) {
	cases := []struct {
		name string
		zone string
		want string
	}{
		{"CNAME+A", baseZone + "www IN CNAME ns1.example.com.\nwww IN A 192.0.2.2\n", "CNAME"},
		{"CNAME+MX", baseZone + "mail IN CNAME ns1.example.com.\nmail IN MX 10 ns1.example.com.\n", "CNAME"},
		{"two CNAME targets", baseZone + "alias IN CNAME a.example.com.\nalias IN CNAME b.example.com.\n", "CNAME"},
		{"escaped spelling CNAME+A", baseZone + "www IN CNAME ns1.example.com.\n\\119ww IN A 192.0.2.2\n", "CNAME"},
		{"apex CNAME", baseZone + "@ IN CNAME other.example.\n", "apex"},
		{"DNAME+CNAME", baseZone + "d IN DNAME other.example.\nd IN CNAME ns1.example.com.\n", "CNAME"},
		{"data beneath DNAME", baseZone + "d IN DNAME other.example.\nx.d IN A 192.0.2.9\n", "DNAME"},
		{"non-glue at delegation", baseZone + "sub IN NS ns.sub.example.com.\nns.sub IN A 192.0.2.5\nsub IN MX 10 ns1.example.com.\n", "delegation"},
		{"DS without delegation", baseZone + "nope IN DS 12345 15 2 ABCD\n", "DS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := newSemZone(t, "nsec", baseZone+"www IN A 192.0.2.10\n")
			if err := z.signer.SignZone(z.domain); err != nil {
				t.Fatalf("baseline sign: %v", err)
			}
			prior, err := os.ReadFile(z.outputPath())
			if err != nil {
				t.Fatal(err)
			}
			priorState := *z.state.GetZone(z.domain)

			z.setZone(t, tc.zone)
			if err := ValidateZoneFile(z.domain, z.zonePath); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateZoneFile must reject (%s), got %v", tc.want, err)
			}
			if err := z.signer.SignZone(z.domain); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SignZone must reject (%s), got %v", tc.want, err)
			}
			now, _ := os.ReadFile(z.outputPath())
			if !bytes.Equal(prior, now) {
				t.Fatal("prior signed output must be left intact")
			}
			if zs := z.state.GetZone(z.domain); zs.LastSigned != priorState.LastSigned || zs.Serial != priorState.Serial {
				t.Fatal("zone state must be left intact")
			}
		})
	}
}

func TestValidateZone_AcceptsLegitimateCNAMEAndDelegations(t *testing.T) {
	for _, mode := range []string{"nsec", "nsec3"} {
		t.Run(mode, func(t *testing.T) {
			z := newSemZone(t, mode, baseZone+`www	IN	CNAME	ns1.example.com.
alias	IN	CNAME	www.example.com.
d	IN	DNAME	other.example.
sub	IN	NS	ns.sub.example.com.
sub	IN	DS	12345 15 2 2BB183AF5F22588179A53B0A98631FAD1A292118
ns.sub	IN	A	192.0.2.5
ns.sub	IN	AAAA	2001:db8::5
insecure	IN	NS	ns1.example.com.
deep.ent.chain	IN	TXT	"under an empty non-terminal"
`)
			if err := ValidateZoneFile(z.domain, z.zonePath); err != nil {
				t.Fatalf("valid zone rejected: %v", err)
			}
			if err := z.signer.SignZone(z.domain); err != nil {
				t.Fatalf("SignZone: %v", err)
			}
			records := parseSigned(t, z.outputPath(), z.domain)
			unsigned := map[wireRRset]bool{
				{wireKey(t, "sub.example.com."), dns.TypeNS}:      true,
				{wireKey(t, "ns.sub.example.com."), dns.TypeA}:    true,
				{wireKey(t, "ns.sub.example.com."), dns.TypeAAAA}: true,
				{wireKey(t, "insecure.example.com."), dns.TypeNS}: true,
			}
			sets := independentVerify(t, records, unsigned)
			if len(sets[wireRRset{wireKey(t, "sub.example.com."), dns.TypeDS}]) != 1 {
				t.Fatal("DS at the delegation must be published and signed")
			}
			// A previously signed output fed back as input (CNAME beside its
			// generated metadata) still validates.
			if err := ValidateZoneFile(z.domain, z.outputPath()); err != nil {
				t.Fatalf("signed output with CNAME plus DNSSEC metadata must validate: %v", err)
			}
		})
	}
}

// --- RA6X-056: denial-chain completeness ------------------------------------

// signedFixture signs a zone in the given mode and returns the signer, the
// input snapshot and the signed records for mutation.
func signedFixture(t *testing.T, mode string) (*Signer, []dns.RR, []dns.RR, *signingKeys) {
	t.Helper()
	z := newSemZone(t, mode, baseZone+`www	IN	A	192.0.2.10
deep.ent	IN	TXT	"x"
sub	IN	NS	ns.sub.example.com.
sub	IN	DS	12345 15 2 2BB183AF5F22588179A53B0A98631FAD1A292118
ns.sub	IN	A	192.0.2.5
`)
	zs := z.state.GetZone(z.domain)
	kg := NewKeyGenerator(z.cfg)
	keys, err := z.signer.loadKeysForSigning(z.domain, kg, zs)
	if err != nil {
		t.Fatal(err)
	}
	records, _, err := z.signer.parseZoneFile(z.domain, z.zonePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys.dnskeys {
		k.Hdr.Ttl = 3600
		records = append(records, k)
	}
	input := append([]dns.RR(nil), records...)
	if mode == "nsec3" {
		chain, err := z.signer.generateNSEC3Chain(z.domain, records, 86400)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, chain...)
	} else {
		records = append(records, z.signer.generateNSECChain(z.domain, records, 86400)...)
	}
	signed, err := z.signer.signRecordsWithKeys(z.domain, records, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := z.signer.verifySignedZone(z.domain, input, signed, keys); err != nil {
		t.Fatalf("fixture must verify: %v", err)
	}
	return z.signer, input, signed, keys
}

// resign re-signs the denial records of a mutated record set so only the
// chain semantics — not the signatures — are under test.
func resign(t *testing.T, s *Signer, domain string, records []dns.RR, keys *signingKeys) []dns.RR {
	t.Helper()
	var data []dns.RR
	for _, rr := range records {
		if _, ok := rr.(*dns.RRSIG); ok {
			continue
		}
		data = append(data, rr)
	}
	out, err := s.signRecordsWithKeys(domain, data, keys)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifySignedZone_DenialChainExpectations(t *testing.T) {
	type mutation struct {
		name string
		mode string
		mut  func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR
		want string
	}
	dropChain := func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
		var out []dns.RR
		for _, rr := range signed {
			switch v := rr.(type) {
			case *dns.NSEC, *dns.NSEC3, *dns.NSEC3PARAM:
				continue
			case *dns.RRSIG:
				if v.TypeCovered == dns.TypeNSEC || v.TypeCovered == dns.TypeNSEC3 || v.TypeCovered == dns.TypeNSEC3PARAM {
					continue
				}
			}
			out = append(out, rr)
		}
		return out
	}
	cases := []mutation{
		{"nsec: whole chain missing", "nsec", dropChain, "missing"},
		{"nsec3: whole chain missing", "nsec3", dropChain, "NSEC3PARAM"},
		{"nsec: owner omitted, ring reclosed", "nsec", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			var out []dns.RR
			var prev *dns.NSEC
			for _, rr := range signed {
				if n, ok := rr.(*dns.NSEC); ok {
					if canonicalName(n.Hdr.Name) == "www.example.com." {
						prev.NextDomain = n.NextDomain // reclose around the dropped owner
						continue
					}
					prev = n
				}
				out = append(out, rr)
			}
			return resign(t, s, "example.com", out, keys)
		}, "missing the record"},
		{"nsec: wrong bitmap type", "nsec", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			for _, rr := range signed {
				if n, ok := rr.(*dns.NSEC); ok && canonicalName(n.Hdr.Name) == "www.example.com." {
					n.TypeBitMap = []uint16{dns.TypeAAAA, dns.TypeNSEC, dns.TypeRRSIG}
				}
			}
			return resign(t, s, "example.com", signed, keys)
		}, "lists types"},
		{"nsec: missing bitmap type", "nsec", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			for _, rr := range signed {
				if n, ok := rr.(*dns.NSEC); ok && canonicalName(n.Hdr.Name) == "sub.example.com." {
					n.TypeBitMap = []uint16{dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG} // DS dropped
				}
			}
			return resign(t, s, "example.com", signed, keys)
		}, "lists types"},
		{"nsec: extra owner (empty non-terminal)", "nsec", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			var out []dns.RR
			for _, rr := range signed {
				out = append(out, rr)
				if n, ok := rr.(*dns.NSEC); ok && canonicalName(n.Hdr.Name) == "deep.ent.example.com." {
					extra := &dns.NSEC{Hdr: dns.RR_Header{Name: "ent.example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 86400}, NextDomain: n.NextDomain, TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG}}
					n.NextDomain = "ent.example.com."
					out = append(out, extra)
				}
			}
			return resign(t, s, "example.com", out, keys)
		}, "not an authoritative owner"},
		{"nsec: out-of-zone owner", "nsec", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			var out []dns.RR
			for _, rr := range signed {
				out = append(out, rr)
				if n, ok := rr.(*dns.NSEC); ok && canonicalName(n.Hdr.Name) == "www.example.com." {
					extra := &dns.NSEC{Hdr: dns.RR_Header{Name: "www.other.test.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 86400}, NextDomain: n.NextDomain, TypeBitMap: []uint16{dns.TypeNSEC, dns.TypeRRSIG}}
					n.NextDomain = "www.other.test."
					out = append(out, extra)
				}
			}
			return resign(t, s, "example.com", out, keys)
		}, "not an authoritative owner"},
		{"nsec3: owner omitted, ring reclosed", "nsec3", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			target := strings.ToUpper(dns.HashName("www.example.com.", dns.SHA1, 0, ""))
			var out []dns.RR
			var prev *dns.NSEC3
			var dropped *dns.NSEC3
			for _, rr := range signed {
				if n, ok := rr.(*dns.NSEC3); ok {
					if strings.ToUpper(dns.SplitDomainName(n.Hdr.Name)[0]) == target {
						dropped = n
						continue
					}
					prev = n
				}
				out = append(out, rr)
			}
			_ = prev
			for _, rr := range out {
				if n, ok := rr.(*dns.NSEC3); ok && strings.ToUpper(n.NextDomain) == target {
					n.NextDomain = dropped.NextDomain
				}
			}
			return resign(t, s, "example.com", out, keys)
		}, "missing the record"},
		{"nsec3: wrong hash (renamed owner)", "nsec3", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			target := strings.ToUpper(dns.HashName("www.example.com.", dns.SHA1, 0, ""))
			bogus := strings.ToUpper(dns.HashName("bogus.example.com.", dns.SHA1, 0, ""))
			for _, rr := range signed {
				if n, ok := rr.(*dns.NSEC3); ok && strings.ToUpper(dns.SplitDomainName(n.Hdr.Name)[0]) == target {
					n.Hdr.Name = bogus + ".example.com."
				}
			}
			return resign(t, s, "example.com", signed, keys)
		}, "missing the record"},
		{"nsec3: parameter mismatch", "nsec3", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			for _, rr := range signed {
				if n, ok := rr.(*dns.NSEC3); ok {
					n.Iterations = 5
				}
			}
			return resign(t, s, "example.com", signed, keys)
		}, "does not match"},
		{"nsec3: NSEC3PARAM mismatch", "nsec3", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			for _, rr := range signed {
				if p, ok := rr.(*dns.NSEC3PARAM); ok {
					p.Salt = "AABB"
					p.SaltLength = 2
				}
			}
			return resign(t, s, "example.com", signed, keys)
		}, "NSEC3PARAM"},
		{"nsec3: wrong bitmap at delegation", "nsec3", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			target := strings.ToUpper(dns.HashName("sub.example.com.", dns.SHA1, 0, ""))
			for _, rr := range signed {
				if n, ok := rr.(*dns.NSEC3); ok && strings.ToUpper(dns.SplitDomainName(n.Hdr.Name)[0]) == target {
					n.TypeBitMap = []uint16{dns.TypeNS, dns.TypeA} // glue leaked, DS lost
				}
			}
			return resign(t, s, "example.com", signed, keys)
		}, "lists types"},
		{"nsec3: empty non-terminal dropped", "nsec3", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			target := strings.ToUpper(dns.HashName("ent.example.com.", dns.SHA1, 0, ""))
			var out []dns.RR
			var dropped *dns.NSEC3
			for _, rr := range signed {
				if n, ok := rr.(*dns.NSEC3); ok && strings.ToUpper(dns.SplitDomainName(n.Hdr.Name)[0]) == target {
					dropped = n
					continue
				}
				out = append(out, rr)
			}
			for _, rr := range out {
				if n, ok := rr.(*dns.NSEC3); ok && strings.ToUpper(n.NextDomain) == target {
					n.NextDomain = dropped.NextDomain
				}
			}
			return resign(t, s, "example.com", out, keys)
		}, "missing the record"},
		{"nsec3: NSEC records in an NSEC3 zone", "nsec3", func(t *testing.T, s *Signer, signed []dns.RR, keys *signingKeys) []dns.RR {
			signed = append(signed, &dns.NSEC{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 86400}, NextDomain: "example.com.", TypeBitMap: []uint16{dns.TypeSOA}})
			return resign(t, s, "example.com", signed, keys)
		}, "NSEC records present"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, input, signed, keys := signedFixture(t, tc.mode)
			mutated := tc.mut(t, s, signed, keys)
			err := s.verifySignedZone("example.com", input, mutated, keys)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("mutation must be rejected with %q, got %v", tc.want, err)
			}
		})
	}
}

// A generator regression driven through the real SignZone boundary must not
// publish: the previous file and state survive.
func TestSignZone_MutatedGenerationKeepsPreviousOutput(t *testing.T) {
	for _, mode := range []string{"nsec", "nsec3"} {
		t.Run(mode, func(t *testing.T) {
			z := newSemZone(t, mode, baseZone+"www IN A 192.0.2.10\n")
			if err := z.signer.SignZone(z.domain); err != nil {
				t.Fatal(err)
			}
			prior, _ := os.ReadFile(z.outputPath())
			priorSigned := z.state.GetZone(z.domain).LastSigned
			z.setZone(t, baseZone+"www IN A 192.0.2.10\nnew IN A 192.0.2.11\n")
			z.signer.mutateBeforeVerify = func(records []dns.RR) []dns.RR {
				var out []dns.RR
				for _, rr := range records {
					switch rr.(type) {
					case *dns.NSEC, *dns.NSEC3:
						continue
					}
					if sig, ok := rr.(*dns.RRSIG); ok && (sig.TypeCovered == dns.TypeNSEC || sig.TypeCovered == dns.TypeNSEC3) {
						continue
					}
					out = append(out, rr)
				}
				return out
			}
			err := z.signer.SignZone(z.domain)
			if err == nil || !strings.Contains(err.Error(), "post-sign verification failed") {
				t.Fatalf("a zone without its denial chain must not publish, got %v", err)
			}
			now, _ := os.ReadFile(z.outputPath())
			if !bytes.Equal(prior, now) {
				t.Fatal("previous signed output must survive")
			}
			if z.state.GetZone(z.domain).LastSigned != priorSigned {
				t.Fatal("previous state must survive")
			}
		})
	}
}

// --- RA6X-053: occlusion cost proportional to depth --------------------------

func TestZoneModel_OcclusionByAncestorLookup(t *testing.T) {
	var records []dns.RR
	mk := func(s string) dns.RR {
		rr, err := dns.NewRR(s)
		if err != nil {
			t.Fatal(err)
		}
		return rr
	}
	records = append(records, mk("example.com. 3600 IN SOA ns1.example.com. admin.example.com. 1 3600 1800 604800 86400"), mk("example.com. 3600 IN NS ns1.example.com."))
	records = append(records,
		mk("child.example.com. 3600 IN NS ns.child.example.com."),
		mk("ns.child.example.com. 3600 IN A 192.0.2.5"),
		mk("deep.er.child.example.com. 3600 IN A 192.0.2.6"),
		mk(`esc\.aped.example.com. 3600 IN NS ns1.example.com.`),
		mk(`below.esc\.aped.example.com. 3600 IN A 192.0.2.7`),
		mk("below.esc.aped.example.com. 3600 IN A 192.0.2.8"),
		mk("\\099hild.example.com. 3600 IN TXT \"same delegation, other spelling\""),
		mk("childish.example.com. 3600 IN A 192.0.2.9"),
	)
	m := newZoneModel("example.com", records)
	cases := map[string]bool{
		"ns.child.example.com.":         true,
		"deep.er.child.example.com.":    true,
		"child.example.com.":            false,
		"childish.example.com.":         false, // suffix of a delegation name is not below it
		`below.esc\.aped.example.com.`:  true,
		"below.esc.aped.example.com.":   false, // different labels than the escaped delegation
		"\\110s.\\099hild.example.com.": true,
		"example.com.":                  false,
	}
	for name, want := range cases {
		if got := m.isOccluded(canonicalName(name)); got != want {
			t.Errorf("isOccluded(%s) = %v, want %v", name, got, want)
		}
	}
}

// BenchmarkOcclusion measures the occlusion index at increasing sizes: the
// work per lookup is bounded by label depth, so doubling both names and cuts
// should roughly double (not quadruple) the total.
func BenchmarkOcclusion(b *testing.B) {
	for _, n := range []int{1000, 2000, 4000} {
		b.Run(fmt.Sprintf("%dx%d", n, n), func(b *testing.B) {
			var records []dns.RR
			for i := 0; i < n; i++ {
				ns, _ := dns.NewRR(fmt.Sprintf("cut%d.example.com. 3600 IN NS ns.cut%d.example.com.", i, i))
				records = append(records, ns)
			}
			names := make([]string, n)
			for i := range names {
				names[i] = canonicalName(fmt.Sprintf("host%d.example.com.", i))
			}
			m := newZoneModel("example.com", records)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m.occluded = make(map[string]bool)
				for _, name := range names {
					if m.isOccluded(name) {
						b.Fatal("no name is occluded in this fixture")
					}
				}
			}
		})
	}
}

// --- RA6X-001: ordinary KSK rollover never changes algorithm -----------------

func TestKSKRollover_KeepsExistingAlgorithm(t *testing.T) {
	z := newSemZone(t, "nsec", baseZone+"www IN A 192.0.2.10\n")
	// Replace the generated ED25519 keys with ECDSA ones under the ED25519 default
	// config (what an ECDSA import yields).
	kg := NewKeyGenerator(z.cfg)
	ksk, err := kg.GenerateKSKWithAlgorithm(z.domain, "ECDSAP256SHA256")
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSKWithAlgorithm(z.domain, "ECDSAP256SHA256")
	if err != nil {
		t.Fatal(err)
	}
	z.state.SetZone(z.domain, &statepkg.ZoneState{Path: z.zonePath, KSK: ksk, ZSK: zsk})
	if err := z.signer.SignZone(z.domain); err != nil {
		t.Fatal(err)
	}
	rm := NewRolloverManager(z.cfg, z.state)
	if err := rm.StartKSKRollover(z.domain); err != nil {
		t.Fatal(err)
	}
	newKSK, err := kg.LoadPublicKey(z.domain, "ksk")
	if err != nil {
		t.Fatal(err)
	}
	if newKSK.Algorithm != dns.ECDSAP256SHA256 {
		t.Fatalf("new KSK algorithm %d, want ECDSAP256SHA256 (existing algorithm)", newKSK.Algorithm)
	}
	if err := z.signer.SignZone(z.domain); err != nil {
		t.Fatalf("signing during rollover: %v", err)
	}
	retireKSK(t, rm, z.signer, z.domain)
	independentVerify(t, parseSigned(t, z.outputPath(), z.domain), nil)

	// After an explicit ED25519→ECDSA... here ECDSA→ED25519 algorithm rollover
	// completed WITHOUT changing the global configuration, the next ordinary KSK
	// rollover stays on the zone's algorithm.
	z.cfg.DNSSEC.Algorithm = "ECDSAP384SHA384" // config default now differs from both
	if err := rm.StartAlgorithmRollover(z.domain, "ED25519"); err != nil {
		t.Fatal(err)
	}
	if err := z.signer.SignZone(z.domain); err != nil {
		t.Fatalf("signing during algorithm rollover: %v", err)
	}
	retireAlgorithm(t, rm, z.signer, z.domain)
	if err := rm.StartKSKRollover(z.domain); err != nil {
		t.Fatal(err)
	}
	k, err := kg.LoadPublicKey(z.domain, "ksk")
	if err != nil {
		t.Fatal(err)
	}
	if k.Algorithm != dns.ED25519 {
		t.Fatalf("KSK rollover after an algorithm rollover minted algorithm %d, want ED25519", k.Algorithm)
	}
	if err := z.signer.SignZone(z.domain); err != nil {
		t.Fatal(err)
	}
}

func TestSignZone_RejectsIncompleteAlgorithmSet(t *testing.T) {
	z := newSemZone(t, "nsec", baseZone+"www IN A 192.0.2.10\n")
	if err := z.signer.SignZone(z.domain); err != nil {
		t.Fatal(err)
	}
	prior, _ := os.ReadFile(z.outputPath())
	// Inject a ZSK of another algorithm as the live ZSK with no algorithm rollover.
	kg := NewKeyGenerator(z.cfg)
	zsk, err := kg.GenerateZSKWithAlgorithm(z.domain, "ECDSAP256SHA256")
	if err != nil {
		t.Fatal(err)
	}
	zs := z.state.GetZone(z.domain)
	z.state.Mutate(func() { zs.ZSK = zsk })
	err = z.signer.SignZone(z.domain)
	if err == nil || !strings.Contains(err.Error(), "different algorithms") {
		t.Fatalf("an algorithm-incomplete key set must be rejected before output replacement, got %v", err)
	}
	if now, _ := os.ReadFile(z.outputPath()); !bytes.Equal(prior, now) {
		t.Fatal("prior output must be intact")
	}
}

// The post-sign invariant itself: a DNSKEY of an extra algorithm that signs
// nothing is rejected even if the key set check were bypassed.
func TestVerifySignedZone_RequiresEveryAlgorithmToSign(t *testing.T) {
	s, input, signed, keys := signedFixture(t, "nsec")
	extra, _, err := generateDNSSECKey("example.com", "ECDSAP256SHA256", 256)
	if err != nil {
		t.Fatal(err)
	}
	extra.Hdr.Ttl = 3600
	keys.dnskeys = append(keys.dnskeys, extra)
	input = append(input, extra)
	signed = append(signed, extra)
	signed = resign(t, s, "example.com", signed, keys) // re-sign with the original ZSK only
	err = s.verifySignedZone("example.com", input, signed, keys)
	if err == nil || !strings.Contains(err.Error(), "RFC 6840") {
		t.Fatalf("an advertised algorithm that signs nothing must be rejected, got %v", err)
	}
}

// fakeDSProbe answers parent-DS questions for tests.
type fakeDSProbe struct {
	present, absent bool
	ttl             uint32
}

func (f fakeDSProbe) ProbeParentDS(domain string, ksks []*dns.DNSKEY) (ParentDSObservation, error) {
	obs := ParentDSObservation{PresentOnAll: map[uint16]bool{}, AbsentOnAll: map[uint16]bool{}, TTL: f.ttl, Servers: []string{"fake"}}
	for _, k := range ksks {
		obs.PresentOnAll[k.KeyTag()] = f.present
		obs.AbsentOnAll[k.KeyTag()] = f.absent
	}
	return obs, nil
}

// retireKSK drives a KSK rollover from ds_add_wait to completion with the
// propagation waits already elapsed (RA6X-003).
func retireKSK(t *testing.T, rm *RolloverManager, s *Signer, domain string) {
	t.Helper()
	if err := rm.CompleteKSKRollover(domain, time.Now().Add(-2*time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	if err := rm.CheckKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if err := s.SignZone(domain); err != nil {
		t.Fatalf("signing the retiring generation: %v", err)
	}
	if err := rm.CheckKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if r := rm.state.GetZone(domain).Rollover; r != nil {
		t.Fatalf("KSK rollover must be complete, got %+v", r)
	}
}

// retireAlgorithm drives an algorithm rollover from algo_ds_add_wait to
// completion with the old DS already gone and every wait elapsed.
func retireAlgorithm(t *testing.T, rm *RolloverManager, s *Signer, domain string) {
	t.Helper()
	rm.SetParentDSProbe(fakeDSProbe{absent: true, ttl: 1})
	if err := rm.CompleteAlgorithmRollover(domain, time.Now().Add(-2*time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	zs := rm.state.GetZone(domain)
	if err := rm.CheckAlgorithmRollover(domain); err != nil { // → old DS removal wait
		t.Fatal(err)
	}
	if err := rm.CheckAlgorithmRollover(domain); err != nil { // probe: old DS gone
		t.Fatal(err)
	}
	rm.state.Mutate(func() { zs.Rollover.OldDSRemovedAt = time.Now().Add(-2 * time.Hour) })
	if err := rm.CheckAlgorithmRollover(domain); err != nil { // → retiring
		t.Fatal(err)
	}
	if err := s.SignZone(domain); err != nil {
		t.Fatalf("signing the retiring generation: %v", err)
	}
	if err := rm.CheckAlgorithmRollover(domain); err != nil {
		t.Fatal(err)
	}
	if r := rm.state.GetZone(domain).Rollover; r != nil {
		t.Fatalf("algorithm rollover must be complete, got %+v", r)
	}
}
