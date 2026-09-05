package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
	"github.com/spf13/cobra"
)

// importFixture is a data dir with a config file, an unsigned zone and a set
// of BIND-style source keys for the zone, generated in a scratch directory.
type importFixture struct {
	dir      string
	cfgPath  string
	zonePath string
	domain   string
	kskBase  string // import source, without extension
	zskBase  string
	kskTag   uint16
	zskTag   uint16
}

func newImportFixture(t *testing.T, domain string) *importFixture {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	content := fmt.Sprintf("output_dir = %q\ndata_dir = %q\n", filepath.Join(dir, "signed"), dir)
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	zonePath := filepath.Join(dir, "zone.db")
	zone := fmt.Sprintf("%[1]s. 3600 IN SOA ns.%[1]s. admin.%[1]s. 1 3600 600 86400 3600\n%[1]s. 3600 IN NS ns.%[1]s.\nns.%[1]s. 3600 IN A 192.0.2.1\n", domain)
	if err := os.WriteFile(zonePath, []byte(zone), 0644); err != nil {
		t.Fatal(err)
	}
	f := &importFixture{dir: dir, cfgPath: cfgPath, zonePath: zonePath, domain: domain}
	f.kskBase, f.zskBase, f.kskTag, f.zskTag = sourceKeys(t, domain)

	orig := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = orig; importFailpoint = nil })
	return f
}

// sourceKeys generates a KSK/ZSK for domain in a scratch directory and returns
// the base paths of their BIND-compatible files.
func sourceKeys(t *testing.T, domain string) (kskBase, zskBase string, kskTag, zskTag uint16) {
	t.Helper()
	scratch := dnssectest.Config(t, t.TempDir())
	kg := signerpkg.NewKeyGenerator(scratch)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(scratch.KeysDir(), domain+".ksk"), filepath.Join(scratch.KeysDir(), domain+".zsk"), ksk.ID, zsk.ID
}

func (f *importFixture) run(t *testing.T) error {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.Flags().String("ksk", "", "")
	cmd.Flags().String("zsk", "", "")
	if err := cmd.Flags().Set("ksk", f.kskBase); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Flags().Set("zsk", f.zskBase); err != nil {
		t.Fatal(err)
	}
	return runImport(cmd, []string{f.domain, f.zonePath})
}

func (f *importFixture) keysDir() string    { return filepath.Join(f.dir, "keys") }
func (f *importFixture) outputPath() string { return filepath.Join(f.dir, "signed", f.domain+".zone.signed") }
func (f *importFixture) statePath() string  { return filepath.Join(f.dir, "state.json") }

// dirSnapshot maps every regular file under dir to its bytes.
func dirSnapshot(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	snap := map[string][]byte{}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return snap
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		snap[e.Name()] = b
	}
	return snap
}

func assertSameSnapshot(t *testing.T, what string, want, got map[string][]byte) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s changed: had %v, now %v", what, keysOf(want), keysOf(got))
	}
	for name, b := range want {
		if !bytes.Equal(got[name], b) {
			t.Fatalf("%s changed: %s differs", what, name)
		}
	}
}

func keysOf(m map[string][]byte) []string {
	var names []string
	for k := range m {
		names = append(names, k)
	}
	return names
}

func readOrNil(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// publishedTags parses the signed output's DNSKEY RRset.
func publishedTags(t *testing.T, path, domain string) map[uint16]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("signed output: %v", err)
	}
	tags := map[uint16]bool{}
	zp := dns.NewZoneParser(strings.NewReader(string(data)), dns.Fqdn(domain), path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if k, ok := rr.(*dns.DNSKEY); ok {
			tags[k.KeyTag()] = true
		}
	}
	if err := zp.Err(); err != nil {
		t.Fatal(err)
	}
	return tags
}

// Valid keys for the wrong zone are rejected before any artifact changes.
func TestImport_WrongDomainKeysChangeNothing(t *testing.T) {
	f := newImportFixture(t, "import.example")
	f.kskBase, f.zskBase, _, _ = sourceKeys(t, "other.example")
	keysBefore := dirSnapshot(t, f.keysDir())
	cfgBefore := readOrNil(t, f.cfgPath)

	err := f.run(t)
	if err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("import of keys for another zone must be refused with the owner mismatch, got %v", err)
	}
	assertSameSnapshot(t, "keys dir", keysBefore, dirSnapshot(t, f.keysDir()))
	if readOrNil(t, f.outputPath()) != nil {
		t.Fatal("no signed output may be produced")
	}
	if !bytes.Equal(cfgBefore, readOrNil(t, f.cfgPath)) {
		t.Fatal("config file must be untouched")
	}
	if st, err := statepkg.LoadState(f.statePath()); err == nil && st.GetZone(f.domain) != nil {
		t.Fatal("state must not register the zone")
	}
}

// Malformed private material (a 64-byte Ed25519 key whose seed no longer
// matches its public suffix, RA6X-030) is rejected before any write.
func TestImport_CorruptSeedRejectedBeforeAnyWrite(t *testing.T) {
	f := newImportFixture(t, "import.example")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := append([]byte(nil), priv...)
	corrupt[0] ^= 1
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(f.domain), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257, Protocol: 3, Algorithm: dns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	base := filepath.Join(t.TempDir(), "K"+f.domain+".+015+corrupt")
	if err := os.WriteFile(base+".key", []byte(dnskey.String()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	privFile := "Private-key-format: v1.3\nAlgorithm: 15 (ED25519)\nPrivateKey: " + base64.StdEncoding.EncodeToString(corrupt) + "\n"
	if err := os.WriteFile(base+".private", []byte(privFile), 0600); err != nil {
		t.Fatal(err)
	}
	f.kskBase = base
	keysBefore := dirSnapshot(t, f.keysDir())

	err = f.run(t)
	if err == nil || !strings.Contains(err.Error(), "seed") {
		t.Fatalf("corrupt expanded key must be rejected at load, got %v", err)
	}
	assertSameSnapshot(t, "keys dir", keysBefore, dirSnapshot(t, f.keysDir()))
	if readOrNil(t, f.outputPath()) != nil {
		t.Fatal("no signed output may be produced")
	}
}

// Every commit step is fault-injected with pre-existing live keys, a served
// output and a removal marker present: the prior generation is restored
// byte-for-byte, the output is never removed, and a retry then succeeds.
func TestImport_FaultInjectionRestoresPriorArtifacts(t *testing.T) {
	steps := []string{"stage:ksk", "stage:zsk", "sign", "activate:ksk", "activate:zsk", "publish", "save", "config"}
	for _, step := range steps {
		t.Run(step, func(t *testing.T) {
			f := newImportFixture(t, "import.example")

			// Prior generation: live keys from an earlier management period, a
			// served output, and a removal marker from `remove`.
			local := dnssectest.Config(t, f.dir)
			kg := signerpkg.NewKeyGenerator(local)
			if _, err := kg.GenerateKSK(f.domain); err != nil {
				t.Fatal(err)
			}
			if _, err := kg.GenerateZSK(f.domain); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(f.outputPath()), 0755); err != nil {
				t.Fatal(err)
			}
			const served = "; previous signed zone still being served\n"
			if err := os.WriteFile(f.outputPath(), []byte(served), 0644); err != nil {
				t.Fatal(err)
			}
			st := statepkg.NewState(f.statePath())
			st.MarkRemoved(f.domain)
			if err := st.Save(); err != nil {
				t.Fatal(err)
			}
			removedAt, _ := st.RemovedAt(f.domain)
			liveBefore := map[string][]byte{}
			for _, n := range []string{".ksk.key", ".ksk.private", ".zsk.key", ".zsk.private"} {
				liveBefore[n] = readOrNil(t, filepath.Join(f.keysDir(), f.domain+n))
			}
			cfgBefore := readOrNil(t, f.cfgPath)

			importFailpoint = func(s string) error {
				if s == step {
					return errors.New("injected fault at " + step)
				}
				return nil
			}
			if err := f.run(t); err == nil {
				t.Fatalf("import must report the fault at %s", step)
			}

			for n, want := range liveBefore {
				if got := readOrNil(t, filepath.Join(f.keysDir(), f.domain+n)); !bytes.Equal(got, want) {
					t.Fatalf("live %s must be restored byte-for-byte after a fault at %s", n, step)
				}
			}
			if got := readOrNil(t, f.outputPath()); string(got) != served {
				t.Fatalf("served output must be intact after a fault at %s, got %q", step, got)
			}
			if _, err := os.Stat(filepath.Join(f.dir, "signed", "."+f.domain+".zone.signed.import")); err == nil {
				t.Fatal("no staged output may remain")
			}
			if !bytes.Equal(cfgBefore, readOrNil(t, f.cfgPath)) {
				t.Fatalf("config must be untouched after a fault at %s", step)
			}
			reloaded, err := statepkg.LoadState(f.statePath())
			if err != nil {
				t.Fatal(err)
			}
			if reloaded.GetZone(f.domain) != nil {
				t.Fatalf("state must not register the zone after a fault at %s", step)
			}
			if at, ok := reloaded.RemovedAt(f.domain); !ok || !at.Equal(removedAt) {
				t.Fatalf("removal marker must be restored after a fault at %s (got %v, %v)", step, at, ok)
			}
			// The prior generation is still usable.
			if _, _, err := kg.LoadKeyPair(f.domain, "ksk"); err != nil {
				t.Fatalf("prior KSK must load: %v", err)
			}

			// Retry after the interruption.
			importFailpoint = nil
			if err := f.run(t); err != nil {
				t.Fatalf("retry after a fault at %s: %v", step, err)
			}
			tags := publishedTags(t, f.outputPath(), f.domain)
			if len(tags) != 2 || !tags[f.kskTag] || !tags[f.zskTag] {
				t.Fatalf("published DNSKEYs %v, want exactly the imported %d/%d", tags, f.kskTag, f.zskTag)
			}
			reloaded, err = statepkg.LoadState(f.statePath())
			if err != nil {
				t.Fatal(err)
			}
			zs := reloaded.GetZone(f.domain)
			if zs == nil || zs.KSK.ID != f.kskTag || zs.ZSK.ID != f.zskTag {
				t.Fatalf("state must record the imported keys, got %+v", zs)
			}
			if _, ok := reloaded.RemovedAt(f.domain); ok {
				t.Fatal("removal marker must be cleared by a committed import")
			}
			if !strings.Contains(string(readOrNil(t, f.cfgPath)), `[zones."import.example"]`) {
				t.Fatal("config must list the imported zone")
			}
			for _, role := range []string{"ksk", "zsk"} {
				k, err := kg.LoadPublicKey(f.domain, role)
				if err != nil {
					t.Fatal(err)
				}
				want := f.kskTag
				if role == "zsk" {
					want = f.zskTag
				}
				if k.KeyTag() != want {
					t.Fatalf("live %s must be the imported key %d, got %d", role, want, k.KeyTag())
				}
			}
		})
	}
}

// A fresh import (no prior keys or output) that fails at the final config
// append leaves nothing published: the output it created is removed, the live
// slots it filled are emptied (their staged tag-named copies remain), and a
// retry commits cleanly.
func TestImport_FreshZoneFaultAtConfigPublishesNothing(t *testing.T) {
	f := newImportFixture(t, "fresh.example")
	importFailpoint = func(s string) error {
		if s == "config" {
			return errors.New("injected config fault")
		}
		return nil
	}
	if err := f.run(t); err == nil {
		t.Fatal("import must report the config fault")
	}
	if readOrNil(t, f.outputPath()) != nil {
		t.Fatal("output created by the failed import must be removed")
	}
	for _, n := range []string{".ksk.key", ".ksk.private", ".zsk.key", ".zsk.private"} {
		if readOrNil(t, filepath.Join(f.keysDir(), f.domain+n)) != nil {
			t.Fatalf("live slot %s must be empty again", n)
		}
	}
	for _, staged := range []string{fmt.Sprintf("%s.ksk.%d.private", f.domain, f.kskTag), fmt.Sprintf("%s.zsk.%d.private", f.domain, f.zskTag)} {
		if readOrNil(t, filepath.Join(f.keysDir(), staged)) == nil {
			t.Fatalf("staged copy %s must be kept", staged)
		}
	}
	if st, err := statepkg.LoadState(f.statePath()); err != nil || st.GetZone(f.domain) != nil {
		t.Fatalf("state must not list the zone (err %v)", err)
	}
	if strings.Contains(string(readOrNil(t, f.cfgPath)), "[zones.") {
		t.Fatal("config must be untouched")
	}

	importFailpoint = nil
	if err := f.run(t); err != nil {
		t.Fatalf("retry: %v", err)
	}
	tags := publishedTags(t, f.outputPath(), f.domain)
	if len(tags) != 2 || !tags[f.kskTag] || !tags[f.zskTag] {
		t.Fatalf("published DNSKEYs %v, want the imported pair", tags)
	}
}
