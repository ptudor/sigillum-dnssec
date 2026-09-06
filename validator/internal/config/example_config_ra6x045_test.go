package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The shipped example configuration and the keys the FreeBSD walkthrough tells
// operators to set must load under the strict decoder (RA6X-045 verification).
func TestShippedExampleAndWalkthroughKeysLoad(t *testing.T) {
	example, err := filepath.Abs(filepath.Join("..", "..", "dnssec-validator.toml.example"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(example); err != nil {
		t.Fatalf("shipped example config is missing: %v", err)
	}
	if _, err := LoadFromFile(example); err != nil {
		t.Fatalf("the shipped example configuration must load: %v", err)
	}

	walkthrough := `listen_addr = "127.0.0.1:8791"
root_anchors_path = "/var/www/internet.any53.com/dns/anchors/root-anchors.json"
root_anchors_url = "https://internet.any53.com/dns/anchors/root-anchors.json"
recursive_resolver = "127.0.0.1"

[logging]
format = "json"
level = "info"
file = "/var/log/tudordns/dnssec-validator.log"
`
	path := filepath.Join(t.TempDir(), "walkthrough.toml")
	if err := os.WriteFile(path, []byte(walkthrough), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("the QUICKSTART-FREEBSD.md snippet must load under strict decoding: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:8791" {
		t.Fatalf("listen_addr = %q", cfg.ListenAddr)
	}
}
