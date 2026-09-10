package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RDAYBLUEX-011: the last-known-good anchor cache path is validated and
// reachable through both loaders.
func TestRDAYBLUEX011_CachePathConfiguration(t *testing.T) {
	cases := []struct {
		name, cache, anchors string
		want                 string
	}{
		{"default", "/var/lib/sigillum-validator/root-anchors.json", "/etc/sigillum-validator/root-anchors.json", ""},
		{"disabled", "", "/etc/sigillum-validator/root-anchors.json", ""},
		{"relative", "cache/root-anchors.json", "/etc/sigillum-validator/root-anchors.json", "absolute"},
		{"same as operator file", "/etc/sigillum-validator/root-anchors.json", "/etc/sigillum-validator/root-anchors.json", "differ"},
		{"same after cleaning", "/etc/sigillum-validator//./root-anchors.json", "/etc/sigillum-validator/root-anchors.json", "differ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateRootAnchorsCachePath(c.cache, c.anchors)
			if c.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
	cfg := DefaultConfig()
	if cfg.RootAnchorsCachePath != "/var/lib/sigillum-validator/root-anchors.json" {
		t.Fatalf("default cache path %q", cfg.RootAnchorsCachePath)
	}
	cfg.RootAnchorsCachePath = "relative.json"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "root_anchors_cache_path") {
		t.Fatalf("Validate must apply the rule: %v", err)
	}

	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte("root_anchors_cache_path = \"/srv/cache/anchors.json\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := LoadFromFile(p)
	if err != nil || fromFile.RootAnchorsCachePath != "/srv/cache/anchors.json" {
		t.Fatalf("file loader: %+v %v", fromFile, err)
	}
	t.Setenv("ROOT_ANCHORS_CACHE_PATH", "/srv/other/anchors.json")
	fromEnv, err := LoadFromEnv()
	if err != nil || fromEnv.RootAnchorsCachePath != "/srv/other/anchors.json" {
		t.Fatalf("environment loader: %q %v", fromEnv.RootAnchorsCachePath, err)
	}
	t.Setenv("ROOT_ANCHORS_CACHE_PATH", "relative.json")
	if _, err := LoadFromEnv(); err == nil || !strings.Contains(err.Error(), "root_anchors_cache_path") {
		t.Fatalf("the environment loader validates the path: %v", err)
	}
}
