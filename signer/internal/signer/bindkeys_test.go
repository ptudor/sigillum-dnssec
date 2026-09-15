package signer

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
)

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 12, 0, 0, 0, time.UTC) }

func candidateNames(cands []*ImportCandidate) []string {
	var out []string
	for _, c := range cands {
		out = append(out, c.Name())
	}
	return out
}

// A key directory from another signer is described completely: usable
// pairs, SHA-1 pairs, revoked keys, lone halves and foreign owners each end up
// where the operator expects, newest first.
func TestScanBindKeys_DescribesEveryPair(t *testing.T) {
	dir := t.TempDir()
	domain := "migrate.example"
	kskNew, _ := dnssectest.WriteBindKeyPair(t, dir, domain, dns.RSASHA512, 257, day(2025, 11, 11))
	zskNew, _ := dnssectest.WriteBindKeyPair(t, dir, domain, dns.RSASHA512, 256, day(2025, 11, 12))
	kskSHA1, _ := dnssectest.WriteBindKeyPair(t, dir, domain, dns.RSASHA1, 257, day(2018, 8, 19))
	zskED, _ := dnssectest.WriteBindKeyPair(t, dir, domain, dns.ED25519, 256, day(2024, 1, 1))
	revoked, _ := dnssectest.WriteBindKeyPair(t, dir, domain, dns.RSASHA256, 385, day(2020, 1, 1))
	orphan, orphanBase := dnssectest.WriteBindKeyPair(t, dir, domain, dns.ED25519, 257, day(2019, 1, 1))
	if err := os.Remove(orphanBase + ".private"); err != nil {
		t.Fatal(err)
	}
	dnssectest.WriteBindKeyPair(t, dir, "other.example", dns.ED25519, 257, day(2025, 1, 1))
	for _, name := range []string{"dsset-migrate.example.", "zone.db.signed", "Kmigrate.example.+015+00001.key.bak"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cands, err := ScanBindKeys(dir, "MIGRATE.example.")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 6 {
		t.Fatalf("got %d candidates, want 6: %v", len(cands), candidateNames(cands))
	}
	byTag := map[uint16]*ImportCandidate{}
	for _, c := range cands {
		byTag[c.Tag] = c
	}

	c := byTag[kskNew.KeyTag()]
	if c == nil || !c.Usable() || c.Role != "ksk" || c.Bits != 2048 || c.Algorithm != dns.RSASHA512 || !c.Created.Equal(day(2025, 11, 11)) || c.Private == nil || c.DNSKEY.KeyTag() != kskNew.KeyTag() {
		t.Fatalf("new KSK described wrongly: %+v", c)
	}
	if c := byTag[zskNew.KeyTag()]; c == nil || !c.Usable() || c.Role != "zsk" || c.Bits != 2048 {
		t.Fatalf("new ZSK described wrongly: %+v", c)
	}
	c = byTag[kskSHA1.KeyTag()]
	if c == nil || c.Usable() || !strings.Contains(c.Problem, "SHA-1") || c.Role != "ksk" || c.Bits != 2048 || c.Private != nil || c.DNSKEY == nil {
		t.Fatalf("SHA-1 KSK must be listed as unusable with the reason: %+v", c)
	}
	if c := byTag[zskED.KeyTag()]; c == nil || !c.Usable() || c.Bits != 0 || c.Algorithm != dns.ED25519 {
		t.Fatalf("ED25519 ZSK described wrongly: %+v", c)
	}
	c = byTag[revoked.KeyTag()]
	if c == nil || c.Usable() || c.Role != "" || !strings.Contains(c.Problem, "REVOKE") {
		t.Fatalf("a revoked key must be listed with no role and the reason: %+v", c)
	}
	c = byTag[orphan.KeyTag()]
	if c == nil || c.Usable() || c.Role != "ksk" || c.DNSKEY == nil || !strings.Contains(c.Problem, ".private") {
		t.Fatalf("a lone .key must be listed with its identity and the missing half: %+v", c)
	}

	var order []uint16
	for _, c := range cands {
		if c.Tag != orphan.KeyTag() { // its Created falls back to the file mtime
			order = append(order, c.Tag)
		}
	}
	want := []uint16{zskNew.KeyTag(), kskNew.KeyTag(), zskED.KeyTag(), revoked.KeyTag(), kskSHA1.KeyTag()}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("candidates must be newest first: got %v, want %v", order, want)
	}
}

// Halves that do not belong together, and keys for another zone, are refused
// with the reason rather than imported.
func TestDescribeCandidate_MismatchAndWrongOwner(t *testing.T) {
	dir := t.TempDir()
	_, aBase := dnssectest.WriteBindKeyPair(t, dir, "m.example", dns.ED25519, 257, day(2025, 1, 1))
	_, bBase := dnssectest.WriteBindKeyPair(t, dir, "m.example", dns.ED25519, 257, day(2025, 1, 2))
	other, err := os.ReadFile(bBase + ".private")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aBase+".private", other, 0o600); err != nil {
		t.Fatal(err)
	}
	if c := DescribeCandidate("m.example", aBase); c.Usable() || !strings.Contains(c.Problem, "does not correspond") {
		t.Fatalf("mismatched halves must be refused: %+v", c)
	}
	_, oBase := dnssectest.WriteBindKeyPair(t, dir, "other.example", dns.ED25519, 257, day(2025, 1, 1))
	if c := DescribeCandidate("m.example", oBase); c.Usable() || !strings.Contains(c.Problem, "does not match zone") {
		t.Fatalf("a key for another zone must be refused: %+v", c)
	}
	if c := DescribeCandidate("m.example", filepath.Join(dir, "Km.example.+015+00042")); c.Usable() || c.Tag != 42 || c.Algorithm != dns.ED25519 || !strings.Contains(c.Problem, ".key") {
		t.Fatalf("a missing pair must be described by its file name: %+v", c)
	}
}

func fakeCandidate(tag uint16, role string, alg uint8, created time.Time) *ImportCandidate {
	flags := uint16(256)
	if role == "ksk" {
		flags = 257
	}
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "sel.example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     flags,
		Protocol:  3,
		Algorithm: alg,
		PublicKey: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("key-%d", tag))),
	}
	return &ImportCandidate{Base: fmt.Sprintf("/keys/K%d", tag), Tag: tag, Algorithm: alg, Flags: flags, Role: role, Created: created, DNSKEY: k, Private: []byte{1}}
}

func unusable(c *ImportCandidate, problem string) *ImportCandidate {
	c.Problem = problem
	c.Private = nil
	return c
}

func dsFor(c *ImportCandidate) *dns.DS {
	return &dns.DS{Hdr: dns.RR_Header{Name: "sel.example.", Rrtype: dns.TypeDS, Class: dns.ClassINET}, KeyTag: c.Tag, Algorithm: c.Algorithm, DigestType: dns.SHA256, Digest: "ab"}
}

func parentHolding(present []*ImportCandidate, absent []*ImportCandidate) ImportObservation {
	obs := ImportObservation{ParentProbed: true, DSPresentOnAll: map[uint16]bool{}, DSAbsentOnAll: map[uint16]bool{}}
	for _, c := range present {
		obs.ParentDS = append(obs.ParentDS, dsFor(c))
		obs.DSPresentOnAll[c.Tag] = true
	}
	for _, c := range absent {
		obs.DSAbsentOnAll[c.Tag] = true
	}
	return obs
}

func hasWarning(sel *ImportSelection, substr string) bool {
	for _, w := range sel.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// Selection anchors trust at the KSK named by the parent's DS. Served state
// only ranks compatible ZSKs; a conflicting deployment is evidence to report,
// not the chain to preserve.
func TestSelectImportKeys(t *testing.T) {
	auto := TagChoice{}
	pick := func(tag uint16) TagChoice { return TagChoice{Set: true, Tag: tag} }

	t.Run("offline with one pair picks it and says the DS was not checked", func(t *testing.T) {
		k, z := fakeCandidate(1, "ksk", dns.ED25519, day(2025, 1, 1)), fakeCandidate(2, "zsk", dns.ED25519, day(2025, 1, 1))
		sel, err := SelectImportKeys([]*ImportCandidate{k, z}, ImportObservation{}, auto, auto)
		if err != nil {
			t.Fatal(err)
		}
		if sel.KSK != k || sel.ZSK != z || !strings.Contains(sel.KSKReason, "not checked") || !hasWarning(sel, "were not checked") {
			t.Fatalf("%+v", sel)
		}
	})

	t.Run("offline with two KSKs needs --ksk", func(t *testing.T) {
		cands := []*ImportCandidate{fakeCandidate(1, "ksk", dns.ED25519, day(2025, 1, 1)), fakeCandidate(3, "ksk", dns.ED25519, day(2024, 1, 1)), fakeCandidate(2, "zsk", dns.ED25519, day(2025, 1, 1))}
		if _, err := SelectImportKeys(cands, ImportObservation{}, auto, auto); err == nil || !strings.Contains(err.Error(), "--ksk") {
			t.Fatalf("got %v", err)
		}
		sel, err := SelectImportKeys(cands, ImportObservation{}, pick(3), auto)
		if err != nil || sel.KSK.Tag != 3 || sel.KSKReason != "chosen with --ksk" {
			t.Fatalf("explicit choice: %+v, %v", sel, err)
		}
	})

	t.Run("the parent's DS decides the KSK", func(t *testing.T) {
		newer, older := fakeCandidate(1, "ksk", dns.ED25519, day(2025, 1, 1)), fakeCandidate(2, "ksk", dns.ED25519, day(2020, 1, 1))
		z := fakeCandidate(3, "zsk", dns.ED25519, day(2025, 1, 1))
		sel, err := SelectImportKeys([]*ImportCandidate{newer, older, z}, parentHolding([]*ImportCandidate{older}, []*ImportCandidate{newer}), auto, auto)
		if err != nil {
			t.Fatal(err)
		}
		if sel.KSK != older || !strings.Contains(sel.KSKReason, "every parent server") || sel.DSMissing || len(sel.Warnings) != 0 {
			t.Fatalf("%+v", sel)
		}
	})

	t.Run("a parent DS naming a SHA-1 key is explained", func(t *testing.T) {
		good := fakeCandidate(1, "ksk", dns.RSASHA256, day(2025, 1, 1))
		sha1 := unusable(fakeCandidate(5, "ksk", dns.RSASHA1, day(2018, 1, 1)), "ksk key for sel.example uses RSASHA1: SHA-1 signatures are no longer treated as secure")
		z := fakeCandidate(3, "zsk", dns.RSASHA256, day(2025, 1, 1))
		_, err := SelectImportKeys([]*ImportCandidate{good, sha1, z}, parentHolding([]*ImportCandidate{sha1}, []*ImportCandidate{good}), auto, auto)
		if err == nil || !strings.Contains(err.Error(), "cannot be imported") || !strings.Contains(err.Error(), "SHA-1") || !strings.Contains(err.Error(), "5/RSASHA1/SHA256") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("the ZSK signing the served zone wins over a newer one", func(t *testing.T) {
		k := fakeCandidate(1, "ksk", dns.ED25519, day(2025, 1, 1))
		old, newer := fakeCandidate(2, "zsk", dns.ED25519, day(2017, 1, 1)), fakeCandidate(3, "zsk", dns.ED25519, day(2025, 1, 1))
		obs := parentHolding([]*ImportCandidate{k}, nil)
		obs.ServedProbed = true
		obs.Served = ServedKeys{Servers: []string{"a"}, DNSKEYs: []*dns.DNSKEY{k.DNSKEY, old.DNSKEY}, SOASigners: []uint16{2}, DNSKEYSigners: []uint16{1}, DNSKEYTTL: 3600}
		sel, err := SelectImportKeys([]*ImportCandidate{k, old, newer}, obs, auto, auto)
		if err != nil {
			t.Fatal(err)
		}
		if sel.ZSK != old || sel.ZSKReason != "it signs the served zone" || len(sel.Warnings) != 0 {
			t.Fatalf("%+v", sel)
		}
		// Not observed: newest, and said so.
		sel, err = SelectImportKeys([]*ImportCandidate{k, old, newer}, parentHolding([]*ImportCandidate{k}, nil), auto, auto)
		if err != nil || sel.ZSK != newer || !strings.Contains(sel.ZSKReason, "newest") || !strings.Contains(sel.ZSKReason, "not checked") {
			t.Fatalf("%+v, %v", sel, err)
		}
	})

	t.Run("the parent-trusted algorithm wins over a broken served deployment", func(t *testing.T) {
		k := fakeCandidate(6142, "ksk", dns.RSASHA256, day(2015, 1, 1))
		z := fakeCandidate(32649, "zsk", dns.RSASHA256, day(2017, 1, 1))
		servedK := fakeCandidate(16439, "ksk", dns.ED25519, day(2026, 1, 1))
		servedZ := fakeCandidate(36503, "zsk", dns.ED25519, day(2026, 1, 1))
		obs := parentHolding([]*ImportCandidate{k}, nil)
		obs.ServedProbed = true
		obs.Served = ServedKeys{
			Servers:       []string{"a"},
			DNSKEYs:       []*dns.DNSKEY{servedK.DNSKEY, servedZ.DNSKEY},
			SOASigners:    []uint16{servedZ.Tag},
			DNSKEYSigners: []uint16{servedK.Tag},
			DNSKEYTTL:     3600,
		}
		sel, err := SelectImportKeys([]*ImportCandidate{k, z}, obs, auto, auto)
		if err != nil {
			t.Fatal(err)
		}
		if sel.KSK != k || sel.ZSK != z || !strings.Contains(sel.ZSKReason, "only usable ZSK") {
			t.Fatalf("the parent-trusted algorithm must determine the compatible pair: %+v", sel)
		}
		if !hasWarning(sel, "does not contain KSK 6142 trusted by the parent DS") || !hasWarning(sel, "installs that KSK with compatible ZSK 32649") || hasWarning(sel, "not in the DNSKEY RRset served today") {
			t.Fatalf("the broken served deployment must be disclosed: %+v", sel.Warnings)
		}
	})

	t.Run("an explicit ZSK of another algorithm is refused", func(t *testing.T) {
		k := fakeCandidate(1, "ksk", dns.RSASHA256, day(2025, 1, 1))
		z := fakeCandidate(2, "zsk", dns.ED25519, day(2025, 1, 1))
		_, err := SelectImportKeys([]*ImportCandidate{k, z}, ImportObservation{}, pick(1), pick(2))
		if err == nil || !strings.Contains(err.Error(), "must share an algorithm") {
			t.Fatalf("got %v", err)
		}
		_, err = SelectImportKeys([]*ImportCandidate{k, z}, ImportObservation{}, pick(1), auto)
		if err == nil || !strings.Contains(err.Error(), "no usable ZSK with the KSK's algorithm RSASHA256") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("a KSK the parent does not name is flagged as DS missing", func(t *testing.T) {
		k := fakeCandidate(1, "ksk", dns.ED25519, day(2025, 1, 1))
		z := fakeCandidate(2, "zsk", dns.ED25519, day(2025, 1, 1))
		foreign := fakeCandidate(999, "ksk", dns.ED25519, day(2025, 1, 1))
		obs := parentHolding([]*ImportCandidate{foreign}, []*ImportCandidate{k})
		if _, err := SelectImportKeys([]*ImportCandidate{k, z}, obs, auto, auto); err == nil || !strings.Contains(err.Error(), "999/ED25519/SHA256") {
			t.Fatalf("automatic selection must refuse and name the parent's DS, got %v", err)
		}
		sel, err := SelectImportKeys([]*ImportCandidate{k, z}, obs, pick(1), auto)
		if err != nil {
			t.Fatal(err)
		}
		if !sel.DSMissing || !hasWarning(sel, "bogus") {
			t.Fatalf("%+v", sel)
		}
		// Partially propagated: a warning, not DS missing.
		obs.DSAbsentOnAll = map[uint16]bool{}
		sel, err = SelectImportKeys([]*ImportCandidate{k, z}, obs, pick(1), auto)
		if err != nil || sel.DSMissing || !hasWarning(sel, "not all") {
			t.Fatalf("%+v, %v", sel, err)
		}
	})

	t.Run("no DS at the parent: any KSK, with a reminder", func(t *testing.T) {
		older, newer := fakeCandidate(1, "ksk", dns.ED25519, day(2020, 1, 1)), fakeCandidate(2, "ksk", dns.ED25519, day(2025, 1, 1))
		z := fakeCandidate(3, "zsk", dns.ED25519, day(2025, 1, 1))
		obs := ImportObservation{ParentProbed: true, DSPresentOnAll: map[uint16]bool{}, DSAbsentOnAll: map[uint16]bool{1: true, 2: true}}
		sel, err := SelectImportKeys([]*ImportCandidate{older, newer, z}, obs, auto, auto)
		if err != nil {
			t.Fatal(err)
		}
		if sel.KSK != newer || sel.DSMissing || !hasWarning(sel, "insecure") {
			t.Fatalf("%+v", sel)
		}
	})

	t.Run("served-zone warnings", func(t *testing.T) {
		k := fakeCandidate(1, "ksk", dns.ED25519, day(2025, 1, 1))
		z := fakeCandidate(2, "zsk", dns.ED25519, day(2025, 1, 1))
		other := fakeCandidate(77, "zsk", dns.ED25519, day(2025, 1, 1))
		obs := parentHolding([]*ImportCandidate{k}, nil)
		obs.ServedProbed = true
		obs.Served = ServedKeys{Servers: []string{"a"}, Unreachable: []string{"b: timeout"}, DNSKEYs: []*dns.DNSKEY{k.DNSKEY, other.DNSKEY}, SOASigners: []uint16{77}, DNSKEYTTL: 3600}
		sel, err := SelectImportKeys([]*ImportCandidate{k, z}, obs, auto, auto)
		if err != nil {
			t.Fatal(err)
		}
		if !hasWarning(sel, "not in the DNSKEY RRset served today (TTL 3600s)") || !hasWarning(sel, "signed by ZSK 77") || !hasWarning(sel, "did not answer") {
			t.Fatalf("%+v", sel.Warnings)
		}
		obs.Served.StaleSignatures = true
		sel, err = SelectImportKeys([]*ImportCandidate{k, z}, obs, auto, auto)
		if err != nil || !hasWarning(sel, "expired") || hasWarning(sel, "TTL 3600s") {
			t.Fatalf("%+v, %v", sel.Warnings, err)
		}
		obs.Served = ServedKeys{Servers: []string{"a"}}
		sel, err = SelectImportKeys([]*ImportCandidate{k, z}, obs, auto, auto)
		if err != nil || !hasWarning(sel, "currently unsigned") {
			t.Fatalf("%+v, %v", sel.Warnings, err)
		}
		obs = parentHolding([]*ImportCandidate{k}, nil)
		obs.ServedError = "no authoritative server answered"
		sel, err = SelectImportKeys([]*ImportCandidate{k, z}, obs, auto, auto)
		if err != nil || !hasWarning(sel, "could not be consulted") {
			t.Fatalf("%+v, %v", sel.Warnings, err)
		}
	})

	t.Run("explicit tags are checked", func(t *testing.T) {
		k := fakeCandidate(1, "ksk", dns.ED25519, day(2025, 1, 1))
		z := fakeCandidate(2, "zsk", dns.ED25519, day(2025, 1, 1))
		bad := unusable(fakeCandidate(3, "ksk", dns.ED25519, day(2025, 1, 1)), "broken")
		cands := []*ImportCandidate{k, z, bad}
		for tag, want := range map[uint16]string{4: "no key with tag 4", 2: "is a ZSK, not a KSK", 3: "cannot be imported: broken"} {
			if _, err := SelectImportKeys(cands, ImportObservation{}, pick(tag), pick(2)); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("--ksk %d: got %v, want %q", tag, err, want)
			}
		}
		if _, err := SelectImportKeys(cands, ImportObservation{}, pick(1), pick(1)); err == nil || !strings.Contains(err.Error(), "is a KSK, not a ZSK") {
			t.Fatalf("--zsk 1: got %v", err)
		}
	})

	t.Run("no usable KSK lists the problems", func(t *testing.T) {
		bad := unusable(fakeCandidate(3, "ksk", dns.ED25519, day(2025, 1, 1)), "broken")
		z := fakeCandidate(2, "zsk", dns.ED25519, day(2025, 1, 1))
		if _, err := SelectImportKeys([]*ImportCandidate{bad, z}, ImportObservation{}, auto, auto); err == nil || !strings.Contains(err.Error(), "3 (ED25519): broken") {
			t.Fatalf("got %v", err)
		}
	})
}
