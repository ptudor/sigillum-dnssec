//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-017 (daemon): an oversized zone fails visibly, keeps its previous
// signed output and does not stop the other zones from signing. The oversized
// source is a sparse regular file above the 256 MiB source limit, which the
// descriptor size check refuses before any byte is read, so the test allocates
// nothing near the limit.

func rdaybluex017Zone(domain string, serial int) string {
	return "$ORIGIN " + domain + "\n$TTL 3600\n@\tIN\tSOA\tns1." + domain + " admin." + domain + " " +
		strings.TrimSpace(strings.Repeat(" ", 1)) + itoa(serial) + " 3600 1800 604800 86400\n@\tIN\tNS\tns1." + domain + "\nns1\tIN\tA\t192.0.2.1\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestRDAYBLUEX017_OversizedZoneFailsWithoutAffectingOthers(t *testing.T) {
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	cfg.LoadedAt = time.Now().UTC()
	for _, d := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := signerpkg.EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	state := statepkg.NewState(cfg.StatePath())
	keyGen := signerpkg.NewKeyGenerator(cfg)
	zones := map[string]string{"small.example.": "small.zone", "huge.example.": "huge.zone"}
	for domain, file := range zones {
		path := filepath.Join(dataDir, file)
		if err := os.WriteFile(path, []byte(rdaybluex017Zone(domain, 2024011501)), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg.Zones[domain] = config.ZoneConfig{Path: path}
		ksk, err := keyGen.GenerateKSK(domain)
		if err != nil {
			t.Fatal(err)
		}
		zsk, err := keyGen.GenerateZSK(domain)
		if err != nil {
			t.Fatal(err)
		}
		state.SetZone(domain, &statepkg.ZoneState{Path: path, KSK: ksk, ZSK: zsk})
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	d := NewDaemon(cfg, state)
	signer := signerpkg.NewSigner(cfg, state)

	// First cycle: both zones sign.
	d.signAllZones()
	for domain := range zones {
		zs := state.GetZone(domain)
		if zs == nil || zs.LastSigned.IsZero() || len(zs.Errors) != 0 {
			t.Fatalf("%s must sign in the first cycle: %+v", domain, zs)
		}
	}
	hugeOut, err := os.ReadFile(signer.OutputPath("huge.example."))
	if err != nil {
		t.Fatal(err)
	}
	firstSmall := state.GetZone("small.example.").LastSigned

	// The huge zone's source becomes a sparse file above the source limit and
	// the small zone gets an ordinary edit; both are older than the
	// quiescence window so the cycle acts on them now.
	hugePath := cfg.Zones["huge.example."].Path
	if err := os.Truncate(hugePath, (256<<20)+1); err != nil {
		t.Fatal(err)
	}
	smallPath := cfg.Zones["small.example."].Path
	if err := os.WriteFile(smallPath, []byte(rdaybluex017Zone("small.example.", 2024011502)+"www\tIN\tA\t192.0.2.10\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for _, p := range []string{hugePath, smallPath} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(20 * time.Millisecond)

	d.signAllZones()

	small := state.GetZone("small.example.")
	if !small.LastSigned.After(firstSmall) || len(small.Errors) != 0 {
		t.Fatalf("the small zone must still sign in the same cycle: %+v", small)
	}
	huge := state.GetZone("huge.example.")
	var signingErr string
	for _, e := range huge.Errors {
		if strings.HasPrefix(e, "signing: ") {
			signingErr = e
		}
	}
	if signingErr == "" || !strings.Contains(signingErr, "source limit") {
		t.Fatalf("the oversized zone must record a visible signing error naming the limit, got %v", huge.Errors)
	}
	after, err := os.ReadFile(signer.OutputPath("huge.example."))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, hugeOut) {
		t.Fatal("the oversized zone's previous signed output must be unchanged")
	}
	if !huge.LastSigned.Equal(state.GetZone("huge.example.").LastSigned) || huge.SourceSize == (256<<20)+1 {
		t.Fatal("the oversized source must not become the recorded source identity")
	}

	// Restoring a sane source heals the zone and clears the error.
	if err := os.WriteFile(hugePath, []byte(rdaybluex017Zone("huge.example.", 2024011503)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(hugePath, old.Add(time.Minute), old.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	d.signAllZones()
	huge = state.GetZone("huge.example.")
	if len(huge.Errors) != 0 {
		t.Fatalf("a restored source must clear the signing error, got %v", huge.Errors)
	}
	if healed, _ := os.ReadFile(signer.OutputPath("huge.example.")); bytes.Equal(healed, hugeOut) {
		t.Fatal("the restored source must be signed and published")
	}
}
