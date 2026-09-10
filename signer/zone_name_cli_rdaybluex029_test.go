//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-029 (CLI): a zone name outside the managed-zone grammar is
// refused by `add` and `import` before any key, output, config or state file
// changes, and every name the configuration accepts is also accepted by the
// persisted-state validation.

func snapshotTree(t *testing.T, root string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			out[p] = info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRDAYBLUEX029_CLIRefusesBadNamesBeforeAnyMutation(t *testing.T) {
	z := newCLIZones(t, false, "ok.example")
	before := snapshotTree(t, z.dir)
	zonePath := filepath.Join(z.dir, "candidate.zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent("candidate.example")), 0o644); err != nil {
		t.Fatal(err)
	}
	before[zonePath] = int64(len(validZoneContent("candidate.example")))
	bad := []string{
		strings.Repeat("a", 64) + ".example",
		"-lead.example", "trail-.example", "a..b.example", ".lead.example",
		"bücher.example", `a\046b.example`, ".", "../escape", "a/b.example",
	}
	for _, name := range bad {
		err := runAdd(nil, []string{name, zonePath})
		if err == nil || !strings.Contains(err.Error(), "invalid domain name") {
			t.Fatalf("add %q must be refused as an invalid domain name, got %v", name, err)
		}
		cmd := &cobra.Command{}
		cmd.Flags().String("ksk", "", "")
		cmd.Flags().String("zsk", "", "")
		err = runImport(cmd, []string{name, zonePath})
		if err == nil || !strings.Contains(err.Error(), "invalid domain name") {
			t.Fatalf("import %q must be refused as an invalid domain name, got %v", name, err)
		}
	}
	after := snapshotTree(t, z.dir)
	if len(after) != len(before) {
		t.Fatalf("refused commands must not create files: before %d, after %d", len(before), len(after))
	}
	for p, size := range before {
		if after[p] != size {
			t.Fatalf("refused commands must not change %s", p)
		}
	}
	// Accepted spellings load, sign and persist, and the persisted state
	// validates.
	for _, name := range []string{"_acme-challenge.candidate.example", "xn--bcher-kva.example", "trailing.dot.example."} {
		zp := filepath.Join(z.dir, strings.ToLower(strings.TrimSuffix(name, "."))+".zone")
		if err := os.WriteFile(zp, []byte(validZoneContent(strings.TrimSuffix(name, "."))), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := runAdd(nil, []string{name, zp}); err != nil {
			t.Fatalf("add %q must succeed: %v", name, err)
		}
	}
	st, err := statepkg.LoadState(z.cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Validate(); err != nil {
		t.Fatalf("every name accepted by the configuration validates as state: %v", err)
	}
	for _, name := range []string{"_acme-challenge.candidate.example", "xn--bcher-kva.example", "trailing.dot.example."} {
		if st.GetZone(name) == nil {
			t.Fatalf("%q must be persisted", name)
		}
	}
}
