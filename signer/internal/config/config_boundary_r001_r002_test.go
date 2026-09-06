package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R-001: isTOMLTableHeader must recognize a valid table header even when it is
// followed by an inline comment, and array-of-tables headers, and quoted keys
// that themselves contain '#' or ']'.
func TestR001_IsTOMLTableHeader(t *testing.T) {
	yes := []string{
		`[zones."next"]`,
		`[zones."next"] # comment`,
		`  [zones."next"]   # comment`,
		`[[some.array]]`,
		`[[some.array]] # comment`,
		`[zones."a#b"]`,     // '#' inside a quoted key is not a comment
		`[zones."a]b"]`,     // ']' inside a quoted key does not close early
		`[zones.'lit#key']`, // literal-string key with '#'
	}
	for _, l := range yes {
		if !isTOMLTableHeader(l) {
			t.Errorf("isTOMLTableHeader(%q) = false, want true", l)
		}
	}
	no := []string{
		`path = "/x"`,
		`# just a comment`,
		``,
		`key = "[not a header]"`,
		`[unterminated`,
	}
	for _, l := range no {
		if isTOMLTableHeader(l) {
			t.Errorf("isTOMLTableHeader(%q) = true, want false", l)
		}
	}
}

// R-001: removing one zone must not delete a following table whose header carries
// an inline comment (the destructive boundary case).
func TestR001_RemovePreservesFollowingCommentedTables(t *testing.T) {
	cfg := strings.Join([]string{
		`output_dir = "/var/lib/sigillum-signer/signed"`,
		``,
		`[zones."target.example"]`,
		`path = "/etc/zones/target.db"`,
		`algorithm = "ED25519"`,
		``,
		`[zones."next.example"] # keep me`,
		`path = "/etc/zones/next.db"`,
		`registrar = "dynadot"`,
		``,
		`[[registrar.extra]] # also keep`,
		`api_key = "SECRETVALUE"`,
		``,
	}, "\n")

	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(cfg), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := RemoveZoneFromConfigFile(path, "target.example"); err != nil {
		t.Fatalf("RemoveZoneFromConfigFile: %v", err)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	if strings.Contains(got, `target.example`) || strings.Contains(got, "/etc/zones/target.db") {
		t.Errorf("target table was not removed:\n%s", got)
	}
	for _, must := range []string{
		`[zones."next.example"] # keep me`,
		`/etc/zones/next.db`,
		`registrar = "dynadot"`,
		`[[registrar.extra]] # also keep`,
		`api_key = "SECRETVALUE"`,
	} {
		if !strings.Contains(got, must) {
			t.Errorf("removal destroyed content that must survive: %q\n---\n%s", must, got)
		}
	}
}

// R-002 / R-019: config replacement preserves the file's mode (a secrets-bearing
// 0640 config is not loosened) and rewrites atomically.
func TestR002_ConfigWritePreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("output_dir = \"/x\"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := AddZoneToConfigFile(path, "z.example", "/etc/zones/z.db"); err != nil {
		t.Fatalf("AddZoneToConfigFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o640 {
		t.Errorf("config mode = %o after add, want 0640 (must not be loosened)", perm)
	}
	out, _ := os.ReadFile(path)
	if !strings.Contains(string(out), `[zones."z.example"]`) {
		t.Errorf("added zone table missing:\n%s", out)
	}
}
