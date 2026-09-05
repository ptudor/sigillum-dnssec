package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// sourceZone is a signed zone whose unsigned source the test rewrites or
// relocates.
type sourceZone struct {
	d       *Daemon
	cfg     *config.Config
	state   *statepkg.State
	domain  string
	srcA    string
	dataDir string
}

func zoneWith(domain, txt string) string {
	return "$ORIGIN " + domain + ".\n$TTL 3600\n" +
		"@\tIN\tSOA\tns1." + domain + ". admin." + domain + ". 2024011501 3600 1800 604800 86400\n" +
		"@\tIN\tNS\tns1." + domain + ".\n" +
		"ns1\tIN\tA\t192.0.2.1\n" +
		"data\tIN\tTXT\t\"" + txt + "\"\n"
}

func newSourceZone(t *testing.T) *sourceZone {
	t.Helper()
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	domain := "source.example"
	srcA := filepath.Join(dataDir, "a.zone")
	if err := os.WriteFile(srcA, []byte(zoneWith(domain, "AAAAA")), 0644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(srcA, old, old); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: srcA}
	for _, dir := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := signerpkg.EnsureDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	state := statepkg.NewState(cfg.StatePath())
	kg := signerpkg.NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	state.SetZone(domain, &statepkg.ZoneState{Path: srcA, KSK: ksk, ZSK: zsk})
	if err := signerpkg.NewSigner(cfg, state).SignZone(domain); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	return &sourceZone{d: NewDaemon(cfg, state), cfg: cfg, state: state, domain: domain, srcA: srcA, dataDir: dataDir}
}

func (z *sourceZone) outputPath() string {
	return filepath.Join(z.cfg.OutputDir, z.domain+".zone.signed")
}

// publishedTXT returns the TXT data served from the signed output.
func (z *sourceZone) publishedTXT(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(z.outputPath())
	if err != nil {
		t.Fatalf("signed output: %v", err)
	}
	zp := dns.NewZoneParser(strings.NewReader(string(data)), dns.Fqdn(z.domain), z.outputPath())
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if txt, ok := rr.(*dns.TXT); ok {
			return strings.Join(txt.Txt, "")
		}
	}
	return ""
}

// sourceB writes a second source with OLDER mtime and the SAME size as A but
// different RR data — the change that mtime/size bookkeeping cannot see.
func (z *sourceZone) sourceB(t *testing.T) string {
	t.Helper()
	srcB := filepath.Join(z.dataDir, "b.zone")
	if err := os.WriteFile(srcB, []byte(zoneWith(z.domain, "BBBBB")), 0644); err != nil {
		t.Fatal(err)
	}
	a, _ := os.Stat(z.srcA)
	b, _ := os.Stat(srcB)
	if a.Size() != b.Size() {
		t.Fatalf("fixture: sizes differ (%d vs %d)", a.Size(), b.Size())
	}
	older := a.ModTime().Add(-time.Hour)
	if err := os.Chtimes(srcB, older, older); err != nil {
		t.Fatal(err)
	}
	return srcB
}

// --- RA6X-005 ----------------------------------------------------------------

func TestSourcePathChange_PublishesNewSourceOnEveryEntryPoint(t *testing.T) {
	entry := []struct {
		name string
		run  func(t *testing.T, z *sourceZone)
	}{
		{"daemon cycle", func(t *testing.T, z *sourceZone) {
			signed, err := z.d.checkAndSignZone(z.d.takeSnapshot(), z.domain)
			if err != nil || !signed {
				t.Fatalf("daemon must sign the new source (signed=%v err=%v)", signed, err)
			}
		}},
		{"sign (SignAll)", func(t *testing.T, z *sourceZone) {
			if err := signerpkg.NewSigner(z.cfg, z.state).SignAll(); err != nil {
				t.Fatal(err)
			}
		}},
		{"resign", func(t *testing.T, z *sourceZone) {
			cfgPath := filepath.Join(z.dataDir, "config.toml")
			content := "output_dir = " + tomlQuote(z.cfg.OutputDir) + "\ndata_dir = " + tomlQuote(z.dataDir) + "\n[zones." + tomlQuote(z.domain) + "]\npath = " + tomlQuote(z.cfg.Zones[z.domain].Path) + "\n"
			if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			orig := configPath
			configPath = cfgPath
			t.Cleanup(func() { configPath = orig })
			if err := runResign(nil, []string{z.domain}); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, e := range entry {
		t.Run(e.name, func(t *testing.T) {
			z := newSourceZone(t)
			if got := z.publishedTXT(t); got != "AAAAA" {
				t.Fatalf("baseline publishes %q", got)
			}
			srcB := z.sourceB(t)
			z.cfg.Zones[z.domain] = config.ZoneConfig{Path: srcB}
			if e.name == "daemon cycle" {
				z.d.Reload(z.cfg, z.state)
			}
			if e.name == "resign" {
				// runResign loads state from disk under the lock.
				if err := z.state.Save(); err != nil {
					t.Fatal(err)
				}
			}
			e.run(t, z)
			if got := z.publishedTXT(t); got != "BBBBB" {
				t.Fatalf("%s must publish source B, got %q", e.name, got)
			}
			st, err := statepkg.LoadState(z.cfg.StatePath())
			if err != nil {
				t.Fatal(err)
			}
			if e.name != "resign" {
				st = z.state
			}
			if p := st.GetZone(z.domain).Path; p != srcB {
				t.Fatalf("state must record the new source after publication, got %q", p)
			}
		})
	}
}

func tomlQuote(s string) string { return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"` }

func TestSourcePathChange_MissingOrInvalidNewSourceKeepsOldOutput(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(t *testing.T, z *sourceZone) string
	}{
		{"missing", func(t *testing.T, z *sourceZone) string { return filepath.Join(z.dataDir, "nope.zone") }},
		{"invalid", func(t *testing.T, z *sourceZone) string {
			p := filepath.Join(z.dataDir, "bad.zone")
			if err := os.WriteFile(p, []byte("this is not a zone\n"), 0644); err != nil {
				t.Fatal(err)
			}
			return p
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			z := newSourceZone(t)
			prior, _ := os.ReadFile(z.outputPath())
			newPath := tc.make(t, z)
			z.cfg.Zones[z.domain] = config.ZoneConfig{Path: newPath}
			z.d.Reload(z.cfg, z.state)
			signed, err := z.d.checkAndSignZone(z.d.takeSnapshot(), z.domain)
			if signed {
				t.Fatal("a missing/invalid new source must not be published")
			}
			zs := z.state.GetZone(z.domain)
			if tc.name == "invalid" && err == nil {
				t.Fatal("an invalid new source must produce a per-zone error")
			}
			if len(zs.Errors) == 0 {
				t.Fatal("the failure must be recorded on the zone")
			}
			if now, _ := os.ReadFile(z.outputPath()); !bytes.Equal(prior, now) {
				t.Fatal("A's last good signed output must be retained")
			}
			if zs.Path != z.srcA {
				t.Fatalf("the prior source reference must be kept until a successful publication, got %q", zs.Path)
			}
		})
	}
}

// --- RA6X-035 ----------------------------------------------------------------

func TestMissingOutput_IsRegeneratedImmediately(t *testing.T) {
	z := newSourceZone(t)
	if err := os.Remove(z.outputPath()); err != nil {
		t.Fatal(err)
	}
	need, reason := signerpkg.NewSigner(z.cfg, z.state).NeedsSign(z.domain, z.srcA, z.state.GetZone(z.domain))
	if !need || reason != "signed output missing" {
		t.Fatalf("missing output must require signing, got %v %q", need, reason)
	}
	signed, err := z.d.checkAndSignZone(z.d.takeSnapshot(), z.domain)
	if err != nil || !signed {
		t.Fatalf("cycle must restore the output (signed=%v err=%v)", signed, err)
	}
	if got := z.publishedTXT(t); got != "AAAAA" {
		t.Fatalf("restored output publishes %q", got)
	}
	// Steady state afterwards: no re-sign every poll.
	if need, reason := signerpkg.NewSigner(z.cfg, z.state).NeedsSign(z.domain, z.srcA, z.state.GetZone(z.domain)); need {
		t.Fatalf("restored zone must not re-sign every poll (%q)", reason)
	}
}

func TestOutputDirChangeOnReload_RegeneratesAndKeepsOldFile(t *testing.T) {
	z := newSourceZone(t)
	oldOutput := z.outputPath()
	prior, _ := os.ReadFile(oldOutput)

	newCfg := *z.cfg
	newCfg.OutputDir = filepath.Join(z.dataDir, "signed-new")
	newCfg.Zones = map[string]config.ZoneConfig{z.domain: z.cfg.Zones[z.domain]}
	z.d.Reload(&newCfg, z.state)
	signed, err := z.d.checkAndSignZone(z.d.takeSnapshot(), z.domain)
	if err != nil || !signed {
		t.Fatalf("cycle after an output_dir change must regenerate (signed=%v err=%v)", signed, err)
	}
	if _, err := os.Stat(filepath.Join(newCfg.OutputDir, z.domain+".zone.signed")); err != nil {
		t.Fatalf("new output missing: %v", err)
	}
	if now, _ := os.ReadFile(oldOutput); !bytes.Equal(prior, now) {
		t.Fatal("the previously served file must be left in place")
	}
}

func TestUnwritableOutputDestination_ReportsAndKeepsPriorFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("relies on filesystem permissions; not meaningful as root")
	}
	z := newSourceZone(t)
	oldOutput := z.outputPath()
	prior, _ := os.ReadFile(oldOutput)

	newDir := filepath.Join(z.dataDir, "signed-ro")
	if err := os.MkdirAll(newDir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(newDir, 0700)
	newCfg := *z.cfg
	newCfg.OutputDir = newDir
	newCfg.Zones = map[string]config.ZoneConfig{z.domain: z.cfg.Zones[z.domain]}
	z.d.Reload(&newCfg, z.state)
	signed, err := z.d.checkAndSignZone(z.d.takeSnapshot(), z.domain)
	if signed || err == nil {
		t.Fatalf("an unwritable destination must fail visibly (signed=%v err=%v)", signed, err)
	}
	if zs := z.state.GetZone(z.domain); len(zs.Errors) == 0 {
		t.Fatal("the output failure must be recorded on the zone (readiness)")
	}
	if now, _ := os.ReadFile(oldOutput); !bytes.Equal(prior, now) {
		t.Fatal("the previously served file must be left in place")
	}
}

// --- RA6X-042 ----------------------------------------------------------------

func TestSourceSnapshot_FIFOSourceIsRejectedWithoutHanging(t *testing.T) {
	z := newSourceZone(t)
	fifo := filepath.Join(z.dataDir, "fifo.zone")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	z.cfg.Zones[z.domain] = config.ZoneConfig{Path: fifo}
	prior, _ := os.ReadFile(z.outputPath())
	done := make(chan error, 1)
	go func() { done <- signerpkg.NewSigner(z.cfg, z.state).SignZone(z.domain) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("a FIFO source must be rejected, got %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("signing a FIFO source hung")
	}
	if now, _ := os.ReadFile(z.outputPath()); !bytes.Equal(prior, now) {
		t.Fatal("prior output must be intact")
	}
}

func TestSourceSnapshot_InPlaceRewriteDuringReadIsNotPublished(t *testing.T) {
	cases := map[string]string{
		"truncated to a valid SOA/NS prefix": "$ORIGIN source.example.\n$TTL 3600\n@\tIN\tSOA\tns1.source.example. admin.source.example. 2024011502 3600 1800 604800 86400\n@\tIN\tNS\tns1.source.example.\n",
		"rewritten with more data":           zoneWith("source.example", "CCCCC") + "more\tIN\tA\t192.0.2.9\n",
	}
	for name, rewrite := range cases {
		t.Run(name, func(t *testing.T) {
			z := newSourceZone(t)
			prior, _ := os.ReadFile(z.outputPath())
			s := signerpkg.NewSigner(z.cfg, z.state)
			signerpkg.SetAfterSourceRead(s, func(path string) {
				// A non-atomic producer rewrites the same inode while we read.
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0644)
				if err != nil {
					t.Fatal(err)
				}
				f.WriteString(rewrite)
				f.Close()
			})
			err := s.SignZone(z.domain)
			if err == nil || !strings.Contains(err.Error(), "changed while it was being read") {
				t.Fatalf("a source rewritten during the read must not publish, got %v", err)
			}
			if now, _ := os.ReadFile(z.outputPath()); !bytes.Equal(prior, now) {
				t.Fatal("prior output must be intact")
			}
		})
	}
}

func TestSourceSnapshot_AtomicReplaceDuringReadSignsConsistentGeneration(t *testing.T) {
	z := newSourceZone(t)
	s := signerpkg.NewSigner(z.cfg, z.state)
	signerpkg.SetAfterSourceRead(s, func(path string) {
		// An atomic producer renames a new file over the path while we read:
		// our descriptor still holds the complete previous generation.
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, []byte(zoneWith(z.domain, "DDDDD")), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	})
	// Force a sign of the old generation.
	zs := z.state.GetZone(z.domain)
	z.state.Mutate(func() { zs.ForceResign = true })
	if err := s.SignZone(z.domain); err != nil {
		t.Fatalf("an atomic replacement during the read must not break the snapshot: %v", err)
	}
	if got := z.publishedTXT(t); got != "AAAAA" {
		t.Fatalf("the snapshot must publish the complete previous generation, got %q", got)
	}
	// The replacement is then detected and published by the next check.
	signerpkg.SetAfterSourceRead(s, nil)
	need, reason := s.NeedsSign(z.domain, z.srcA, zs)
	if !need {
		t.Fatalf("the atomically replaced source must be detected next (reason %q)", reason)
	}
	if err := s.SignZone(z.domain); err != nil {
		t.Fatal(err)
	}
	if got := z.publishedTXT(t); got != "DDDDD" {
		t.Fatalf("the new generation must publish next, got %q", got)
	}
}
