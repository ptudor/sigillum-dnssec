package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// captureImportOutput runs fn with os.Stdout redirected and returns what it
// printed.
func captureImportOutput(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()
	func() {
		defer func() {
			os.Stdout = orig
			w.Close()
		}()
		fn()
	}()
	<-done
	return buf.String()
}

func keysDirImport(t *testing.T, f *importFixture, flags map[string]string) (string, error) {
	t.Helper()
	cmd := importCmdForTest(t, flags)
	var err error
	out := captureImportOutput(t, func() { err = runImport(cmd, []string{f.domain, f.zonePath}) })
	return out, err
}

func assertNothingImported(t *testing.T, f *importFixture, cfgBefore []byte) {
	t.Helper()
	if readOrNil(t, f.outputPath()) != nil {
		t.Fatal("no signed output may be produced")
	}
	if n := len(dirSnapshot(t, f.keysDir())); n != 0 {
		t.Fatalf("no key files may be written, found %d", n)
	}
	if !bytes.Equal(cfgBefore, readOrNil(t, f.cfgPath)) {
		t.Fatal("config file must be untouched")
	}
	if st, err := statepkg.LoadState(f.statePath()); err == nil && st.GetZone(f.domain) != nil {
		t.Fatal("state must not register the zone")
	}
}

// verifySOASignature checks that the signed output's SOA carries an RRSIG by
// zsk that verifies — the imported key really signed the zone.
func verifySOASignature(t *testing.T, path, domain string, zsk *dns.DNSKEY) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var soa []dns.RR
	var sigs []*dns.RRSIG
	zp := dns.NewZoneParser(strings.NewReader(string(data)), dns.Fqdn(domain), path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch r := rr.(type) {
		case *dns.SOA:
			soa = append(soa, r)
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeSOA {
				sigs = append(sigs, r)
			}
		}
	}
	if err := zp.Err(); err != nil {
		t.Fatal(err)
	}
	if len(soa) != 1 {
		t.Fatalf("signed output has %d SOA records", len(soa))
	}
	for _, sig := range sigs {
		if sig.KeyTag == zsk.KeyTag() {
			if err := sig.Verify(zsk, soa); err != nil {
				t.Fatalf("RRSIG over the SOA by ZSK %d does not verify: %v", zsk.KeyTag(), err)
			}
			return
		}
	}
	t.Fatalf("no RRSIG over the SOA by the imported ZSK %d", zsk.KeyTag())
}

var importDay = time.Date(2025, 11, 11, 0, 0, 0, 0, time.UTC)

// --dry-run shows the inventory and the plan and writes nothing.
func TestImportKeysDir_DryRunWritesNothing(t *testing.T) {
	f := newImportFixture(t, "dryrun.example")
	dir := t.TempDir()
	ksk, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.ED25519, 257, importDay)
	zsk, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.ED25519, 256, importDay)
	cfgBefore := readOrNil(t, f.cfgPath)

	out, err := keysDirImport(t, f, map[string]string{"keys-dir": dir, "dry-run": "true"})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"Keys for dryrun.example", fmt.Sprint(ksk.KeyTag()), fmt.Sprint(zsk.KeyTag()), "Plan for dryrun.example", "not checked", "Dry run: nothing was written."} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	assertNothingImported(t, f, cfgBefore)
}

// A directory holding usable RSA keys, a SHA-1 KSK and a ZSK of another
// algorithm imports the usable RSA pair, lists the rest, and produces a zone
// whose signatures verify under the imported keys.
func TestImportKeysDir_ChoosesUsableRSAPairAndSigns(t *testing.T) {
	f := newImportFixture(t, "rsa.example")
	dir := t.TempDir()
	ksk, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.RSASHA256, 257, importDay)
	zsk, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.RSASHA256, 256, importDay.Add(24*time.Hour))
	sha1, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.RSASHA1, 257, time.Date(2018, 8, 19, 0, 0, 0, 0, time.UTC))
	other, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.ED25519, 256, time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))

	out, err := keysDirImport(t, f, map[string]string{"keys-dir": dir})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"SHA-1", "unusable", fmt.Sprintf("KSK %d (RSASHA256, 2048 bits)", ksk.KeyTag()), fmt.Sprintf("ZSK %d (RSASHA256, 2048 bits)", zsk.KeyTag()), "imported."} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	st, err := statepkg.LoadState(f.statePath())
	if err != nil {
		t.Fatal(err)
	}
	zs := st.GetZone(f.domain)
	if zs == nil || zs.KSK.ID != ksk.KeyTag() || zs.ZSK.ID != zsk.KeyTag() || zs.KSK.Algorithm != "RSASHA256" || zs.ZSK.Algorithm != "RSASHA256" {
		t.Fatalf("zone state after import: %+v", zs)
	}
	tags := publishedTags(t, f.outputPath(), f.domain)
	if !tags[ksk.KeyTag()] || !tags[zsk.KeyTag()] || tags[sha1.KeyTag()] || tags[other.KeyTag()] {
		t.Fatalf("published DNSKEY tags %v", tags)
	}
	verifySOASignature(t, f.outputPath(), f.domain, zsk)
	if priv := readOrNil(t, filepath.Join(f.keysDir(), f.domain+".zsk.private")); !bytes.Contains(priv, []byte("Modulus: ")) {
		t.Fatalf("the live RSA private key must be in BIND's multi-field layout:\n%s", priv)
	}
	if !strings.Contains(string(readOrNil(t, f.cfgPath)), f.domain) {
		t.Fatal("the zone must be registered in the config file")
	}
}

// Two usable KSKs with no parent to consult need an explicit --ksk, and the
// tag form of --ksk selects among the scanned keys.
func TestImportKeysDir_AmbiguousKSKNeedsChoice(t *testing.T) {
	f := newImportFixture(t, "two.example")
	dir := t.TempDir()
	older, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.ED25519, 257, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
	dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.ED25519, 257, importDay)
	dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.ED25519, 256, importDay)
	cfgBefore := readOrNil(t, f.cfgPath)

	out, err := keysDirImport(t, f, map[string]string{"keys-dir": dir})
	if err == nil || !strings.Contains(err.Error(), "--ksk") {
		t.Fatalf("two KSKs offline must require --ksk, got %v\n%s", err, out)
	}
	assertNothingImported(t, f, cfgBefore)

	if out, err := keysDirImport(t, f, map[string]string{"keys-dir": dir, "ksk": fmt.Sprint(older.KeyTag())}); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	st, err := statepkg.LoadState(f.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if zs := st.GetZone(f.domain); zs == nil || zs.KSK.ID != older.KeyTag() {
		t.Fatalf("the chosen KSK must be the one imported: %+v", zs)
	}
}

// Explicit tags are held to the same rules as the automatic choice.
func TestImportKeysDir_ExplicitTagsAreChecked(t *testing.T) {
	f := newImportFixture(t, "refuse.example")
	dir := t.TempDir()
	dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.RSASHA256, 257, importDay)
	dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.RSASHA256, 256, importDay)
	sha1, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.RSASHA1, 257, time.Date(2018, 8, 19, 0, 0, 0, 0, time.UTC))
	ed, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.ED25519, 256, importDay)
	cfgBefore := readOrNil(t, f.cfgPath)

	if _, err := keysDirImport(t, f, map[string]string{"keys-dir": dir, "ksk": fmt.Sprint(sha1.KeyTag())}); err == nil || !strings.Contains(err.Error(), "SHA-1") {
		t.Fatalf("a SHA-1 KSK chosen by tag must be refused with the reason, got %v", err)
	}
	if _, err := keysDirImport(t, f, map[string]string{"keys-dir": dir, "zsk": fmt.Sprint(ed.KeyTag())}); err == nil || !strings.Contains(err.Error(), "must share an algorithm") {
		t.Fatalf("a ZSK of another algorithm chosen by tag must be refused, got %v", err)
	}
	if _, err := keysDirImport(t, f, map[string]string{"keys-dir": dir, "zsk": "4242"}); err == nil || !strings.Contains(err.Error(), "no key with tag 4242") {
		t.Fatalf("an unknown tag must be refused, got %v", err)
	}
	assertNothingImported(t, f, cfgBefore)
}

// With --keys-dir, --ksk/--zsk may still be a path: that pair joins the
// scanned candidates.
func TestImportKeysDir_PathFlagJoinsCandidates(t *testing.T) {
	f := newImportFixture(t, "mixed.example")
	dir := t.TempDir()
	ksk, _ := dnssectest.WriteBindKeyPair(t, dir, f.domain, dns.ED25519, 257, importDay)
	zsk, zskBase := dnssectest.WriteBindKeyPair(t, t.TempDir(), f.domain, dns.ED25519, 256, importDay)

	if out, err := keysDirImport(t, f, map[string]string{"keys-dir": dir, "zsk": zskBase}); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	st, err := statepkg.LoadState(f.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if zs := st.GetZone(f.domain); zs == nil || zs.KSK.ID != ksk.KeyTag() || zs.ZSK.ID != zsk.KeyTag() {
		t.Fatalf("zone state after import: %+v", zs)
	}
}

// Without --keys-dir both key paths are required.
func TestImport_RequiresKeysDirOrBothPaths(t *testing.T) {
	f := newImportFixture(t, "flags.example")
	cmd := importCmdForTest(t, map[string]string{"ksk": f.kskBase})
	err := runImport(cmd, []string{f.domain, f.zonePath})
	if err == nil || !strings.Contains(err.Error(), "--keys-dir") {
		t.Fatalf("got %v", err)
	}
}
