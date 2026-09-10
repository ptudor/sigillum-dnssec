package signer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-017: zone-file input is bounded in bytes and records before and
// during parsing. RDAYBLUEX-016: change detection compares the exact source
// bytes, so a same-size, same-or-older-mtime replacement is signed and an
// unchanged file with new metadata is not.

type sourceLab struct {
	cfg    *config.Config
	s      *Signer
	state  *statepkg.State
	domain string
	path   string
}

func newSourceLab(t *testing.T) *sourceLab {
	t.Helper()
	dir := t.TempDir()
	cfg := dnssectest.Config(t, dir)
	for _, d := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	domain := "bounds.example."
	path := filepath.Join(dir, "bounds.zone")
	if err := os.WriteFile(path, []byte(boundsZone(domain, 0)), 0o644); err != nil {
		t.Fatal(err)
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
	state := statepkg.NewState(cfg.StatePath())
	state.SetZone(domain, &statepkg.ZoneState{Path: path, KSK: ksk, ZSK: zsk})
	return &sourceLab{cfg: cfg, s: NewSigner(cfg, state), state: state, domain: domain, path: path}
}

// boundsZone is a small zone with extra records appended.
func boundsZone(domain string, extra int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "$ORIGIN %s\n$TTL 3600\n@\tIN\tSOA\tns1.%s admin.%s 2024011501 3600 1800 604800 86400\n@\tIN\tNS\tns1.%s\nns1\tIN\tA\t192.0.2.1\n", domain, domain, domain, domain)
	for i := 0; i < extra; i++ {
		fmt.Fprintf(&b, "h%04d\tIN\tA\t192.0.2.%d\n", i, 10+i%200)
	}
	return b.String()
}

func setSourceLimits(t *testing.T, bytes int64, records int) {
	t.Helper()
	ob, or := maxZoneFileBytes, maxZoneRecords
	maxZoneFileBytes, maxZoneRecords = bytes, records
	t.Cleanup(func() { maxZoneFileBytes, maxZoneRecords = ob, or })
}

func TestRDAYBLUEX017_ByteAndRecordBounds(t *testing.T) {
	lab := newSourceLab(t)
	content := boundsZone(lab.domain, 3)
	// Pad with a comment so the file lands exactly on the byte limit.
	padTo := func(n int) string {
		c := content
		for len(c) < n-1 {
			c += ";"
		}
		return c + "\n"
	}
	limit := int64(len(content) + 40)
	setSourceLimits(t, limit, 100)

	for _, n := range []int{int(limit) - 1, int(limit)} {
		if err := os.WriteFile(lab.path, []byte(padTo(n)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := lab.s.SignZone(lab.domain); err != nil {
			t.Fatalf("%d bytes (limit %d) must sign: %v", n, limit, err)
		}
	}
	good, err := os.ReadFile(lab.s.OutputPath(lab.domain))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lab.path, []byte(padTo(int(limit)+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := lab.s.SignZone(lab.domain); err == nil || !strings.Contains(err.Error(), "source limit") {
		t.Fatalf("limit+1 bytes must be rejected before reading, got %v", err)
	}
	if now, _ := os.ReadFile(lab.s.OutputPath(lab.domain)); string(now) != string(good) {
		t.Fatal("a rejected zone keeps its last-known-good output")
	}
	if err := ValidateZoneFile(lab.domain, lab.path); err == nil || !strings.Contains(err.Error(), "source limit") {
		t.Fatalf("ValidateZoneFile applies the same byte limit, got %v", err)
	}

	// A sparse regular file whose size exceeds the limit is rejected by its
	// size alone.
	if err := os.WriteFile(lab.path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(lab.path, limit*4); err != nil {
		t.Fatal(err)
	}
	if err := lab.s.SignZone(lab.domain); err == nil || !strings.Contains(err.Error(), "above the") {
		t.Fatalf("a sparse oversized file must be rejected by its size, got %v", err)
	}

	// Record bound: max-1 and max records parse, max+1 is refused.
	setSourceLimits(t, 1<<20, 3+5) // SOA, NS, ns1 A + 5 hosts
	for _, extra := range []int{4, 5} {
		if err := os.WriteFile(lab.path, []byte(boundsZone(lab.domain, extra)), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := lab.s.SignZone(lab.domain); err != nil {
			t.Fatalf("%d records must sign: %v", 3+extra, err)
		}
	}
	if err := os.WriteFile(lab.path, []byte(boundsZone(lab.domain, 6)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := lab.s.SignZone(lab.domain); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("one record over the limit must be refused, got %v", err)
	}
	if err := ValidateZoneFile(lab.domain, lab.path); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("ValidateZoneFile applies the record limit, got %v", err)
	}

	// A single extremely long record is bounded by bytes like anything else.
	setSourceLimits(t, 4096, 1000)
	long := boundsZone(lab.domain, 0) + "big\tIN\tTXT\t\"" + strings.Repeat("x", 5000) + "\"\n"
	if err := os.WriteFile(lab.path, []byte(long), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := lab.s.SignZone(lab.domain); err == nil || !strings.Contains(err.Error(), "source limit") {
		t.Fatalf("a huge single record is refused by the byte bound, got %v", err)
	}
}

// A file that grows during the read is refused (the existing consistency
// rule), and the read itself never exceeds the bound.
func TestRDAYBLUEX017_GrowthDuringReadIsRefused(t *testing.T) {
	lab := newSourceLab(t)
	setSourceLimits(t, 1<<16, 1000)
	if err := os.WriteFile(lab.path, []byte(boundsZone(lab.domain, 2)), 0o644); err != nil {
		t.Fatal(err)
	}
	SetAfterSourceRead(lab.s, func(path string) {
		f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		_, _ = f.WriteString("late\tIN\tA\t192.0.2.99\n")
		f.Close()
	})
	if err := lab.s.SignZone(lab.domain); err == nil || !strings.Contains(err.Error(), "changed while it was being read") {
		t.Fatalf("growth during the read must be refused, got %v", err)
	}
}

func TestRDAYBLUEX016_ContentIdentityDrivesChangeDetection(t *testing.T) {
	lab := newSourceLab(t)
	content := boundsZone(lab.domain, 2)
	if err := os.WriteFile(lab.path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := lab.s.SignZone(lab.domain); err != nil {
		t.Fatal(err)
	}
	zs := lab.state.GetZone(lab.domain)
	if zs.SourceDigest == "" {
		t.Fatal("signing must record the source digest")
	}
	// Push signature expiry far out so only source changes decide.
	lab.state.Mutate(func() { zs.SignaturesExp = time.Now().Add(24 * time.Hour) })
	origMtime := zs.SourceModTime
	if need, _ := lab.s.NeedsSign(lab.domain, lab.path, zs); need {
		t.Fatal("an unchanged file must not need signing")
	}

	// Same length, different content, mtime preserved: must sign.
	changed := strings.Replace(content, "192.0.2.10", "192.0.2.11", 1)
	if len(changed) != len(content) {
		t.Fatal("test replacement must keep the length")
	}
	replaceAtomically(t, lab.path, changed, origMtime)
	need, reason := lab.s.NeedsSign(lab.domain, lab.path, zs)
	if !need || !strings.Contains(reason, "content changed") {
		t.Fatalf("a same-size preserved-mtime replacement must be signed (need=%v reason=%q)", need, reason)
	}
	if err := lab.s.SignZone(lab.domain); err != nil {
		t.Fatal(err)
	}
	zs = lab.state.GetZone(lab.domain)
	lab.state.Mutate(func() { zs.SignaturesExp = time.Now().Add(24 * time.Hour) })

	// Older mtime, same size, different content: must sign.
	older := strings.Replace(changed, "192.0.2.11", "192.0.2.12", 1)
	replaceAtomically(t, lab.path, older, zs.SourceModTime.Add(-time.Hour))
	if need, _ := lab.s.NeedsSign(lab.domain, lab.path, zs); !need {
		t.Fatal("an older-mtime replacement with different content must be signed")
	}
	if err := lab.s.SignZone(lab.domain); err != nil {
		t.Fatal(err)
	}
	zs = lab.state.GetZone(lab.domain)
	lab.state.Mutate(func() { zs.SignaturesExp = time.Now().Add(24 * time.Hour) })

	// Byte-for-byte replacement with a newer mtime: not re-signed; the
	// metadata reference is refreshed.
	replaceAtomically(t, lab.path, older, zs.SourceModTime.Add(2*time.Hour))
	if need, _ := lab.s.NeedsSign(lab.domain, lab.path, zs); need {
		t.Fatal("identical bytes with a newer mtime must not be re-signed")
	}
	if info, _ := os.Stat(lab.path); !zs.SourceModTime.Equal(info.ModTime()) {
		t.Fatal("the metadata reference must be refreshed to the new mtime")
	}

	// A write observed during the digest read updates nothing.
	before := zs.SourceDigest
	SetAfterSourceRead(lab.s, func(path string) {
		f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
		_, _ = f.WriteString("; mid-write\n")
		f.Close()
	})
	if need, _ := lab.s.NeedsSign(lab.domain, lab.path, zs); need {
		t.Fatal("an inconsistent read must defer, not decide")
	}
	if zs.SourceDigest != before {
		t.Fatal("an inconsistent read must not update the stored identity")
	}
	SetAfterSourceRead(lab.s, nil)
}

// An old state file without a digest establishes a baseline from the
// current file without re-signing and without losing the current output.
func TestRDAYBLUEX016_LegacyStateEstablishesBaseline(t *testing.T) {
	lab := newSourceLab(t)
	if err := lab.s.SignZone(lab.domain); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(lab.s.OutputPath(lab.domain))
	zs := lab.state.GetZone(lab.domain)
	lab.state.Mutate(func() {
		zs.SourceDigest = "" // as written by a version before digests existed
		zs.SignaturesExp = time.Now().Add(24 * time.Hour)
	})
	need, _ := lab.s.NeedsSign(lab.domain, lab.path, zs)
	if need {
		t.Fatal("unchanged metadata with no recorded digest must not re-sign")
	}
	if zs.SourceDigest == "" {
		t.Fatal("the baseline digest must be recorded")
	}
	if now, _ := os.ReadFile(lab.s.OutputPath(lab.domain)); string(now) != string(out) {
		t.Fatal("establishing the baseline must not touch the output")
	}
	// From the baseline on, a preserved-mtime content change is detected.
	c, _ := os.ReadFile(lab.path)
	changed := strings.Replace(string(c), "192.0.2.1\n", "192.0.2.2\n", 1)
	replaceAtomically(t, lab.path, changed, zs.SourceModTime)
	if need, _ := lab.s.NeedsSign(lab.domain, lab.path, zs); !need {
		t.Fatal("after the baseline a hidden content change must be detected")
	}
}

// replaceAtomically writes content to a temporary file with the given mtime
// and renames it over path.
func replaceAtomically(t *testing.T, path, content string, mtime time.Time) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(tmp, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}
