package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// R-008: RemoveZoneFromConfigFile deletes exactly the named zone's table, preserving other
// zones and comments, keeping the file mode, and leaving valid TOML.
func TestRemoveZoneFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	content := `output_dir = "/var/signed"
data_dir = "/var/lib"

[dnssec]
algorithm = "ED25519"

# keep this comment
[zones."a.example.com"]
path = "/zones/a.db"

[zones."b.example.com"]
path = "/zones/b.db"
registrar = "dynadot"

[zones."c.example.com"]
path = "/zones/c.db"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}

	if err := RemoveZoneFromConfigFile(cfgPath, "b.example.com"); err != nil {
		t.Fatalf("remove middle zone: %v", err)
	}

	out, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	if strings.Contains(got, "b.example.com") || strings.Contains(got, "/zones/b.db") || strings.Contains(got, "dynadot") {
		t.Errorf("removed zone b still present:\n%s", got)
	}
	if !strings.Contains(got, "a.example.com") || !strings.Contains(got, "c.example.com") {
		t.Errorf("sibling zones must be preserved:\n%s", got)
	}
	if !strings.Contains(got, "# keep this comment") {
		t.Errorf("comments must be preserved:\n%s", got)
	}

	// Mode preserved (a 0640 secrets-bearing config must not be loosened to 0644).
	if info, _ := os.Stat(cfgPath); info.Mode().Perm() != 0640 {
		t.Errorf("config mode = %o, want 0640", info.Mode().Perm())
	}

	// Still valid TOML with exactly the surviving zones.
	var parsed Config
	if err := toml.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("result is not valid TOML: %v", err)
	}
	if _, ok := parsed.Zones["b.example.com"]; ok {
		t.Error("b still parses from the config")
	}
	if _, ok := parsed.Zones["a.example.com"]; !ok {
		t.Error("a missing from parsed config")
	}
	if _, ok := parsed.Zones["c.example.com"]; !ok {
		t.Error("c missing from parsed config")
	}

	// Removing an absent zone reports the sentinel (so `remove` can proceed).
	if err := RemoveZoneFromConfigFile(cfgPath, "z.example.com"); err != errZoneNotInConfig {
		t.Errorf("expected errZoneNotInConfig for absent zone, got %v", err)
	}
}
