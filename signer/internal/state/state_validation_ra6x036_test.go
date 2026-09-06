package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RA6X-036: syntactically valid but malformed state must be rejected (or
// normalized) at load time instead of panicking later or being signed through.

func writeState(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRA6X036_NullZoneMapIsEmpty(t *testing.T) {
	st, err := LoadState(writeState(t, `{"zones": null}`))
	if err != nil {
		t.Fatalf("{\"zones\":null} must load as an empty state: %v", err)
	}
	if st.Zones == nil {
		t.Fatal("zone map must be initialized, not nil")
	}
	// A later write must not panic on a nil map.
	st.SetZone("example.com", &ZoneState{Path: "/z"})
	if err := st.Save(); err != nil {
		t.Fatalf("save after null-map load: %v", err)
	}
}

func TestRA6X036_InvalidDocumentsAreRejectedAndLeftUnchanged(t *testing.T) {
	cases := map[string]string{
		"null zone entry":                  `{"zones": {"example.com": null}}`,
		"empty zone name":                  `{"zones": {"": {"path": "/z"}}}`,
		"invalid zone name":                `{"zones": {"exa mple..com": {"path": "/z"}}}`,
		"signed without path":              `{"zones": {"example.com": {"path": "", "last_signed": "2024-01-15T10:00:00Z"}}}`,
		"key without algorithm":            `{"zones": {"example.com": {"path": "/z", "ksk": {"id": 5}}}}`,
		"unknown rollover state":           `{"zones": {"example.com": {"path": "/z", "ksk": {"id": 2, "algorithm": "ED25519"}, "rollover": {"type": "ksk", "state": "bogus_phase", "old_key_id": 1, "new_key_id": 2}}}}`,
		"unknown rollover type":            `{"zones": {"example.com": {"path": "/z", "ksk": {"id": 2, "algorithm": "ED25519"}, "rollover": {"type": "kaboom", "state": "ds_add_wait", "old_key_id": 1, "new_key_id": 2}}}}`,
		"ksk rollover same ids":            `{"zones": {"example.com": {"path": "/z", "ksk": {"id": 2, "algorithm": "ED25519"}, "rollover": {"type": "ksk", "state": "ds_add_wait", "old_key_id": 2, "new_key_id": 2}}}}`,
		"ksk rollover wrong live":          `{"zones": {"example.com": {"path": "/z", "ksk": {"id": 9, "algorithm": "ED25519"}, "rollover": {"type": "ksk", "state": "ds_add_wait", "old_key_id": 1, "new_key_id": 2}}}}`,
		"ksk rollover no key":              `{"zones": {"example.com": {"path": "/z", "rollover": {"type": "ksk", "state": "ds_add_wait", "old_key_id": 1, "new_key_id": 2}}}}`,
		"zsk prepublish wrong live":        `{"zones": {"example.com": {"path": "/z", "zsk": {"id": 333, "algorithm": "ED25519"}, "rollover": {"type": "zsk", "state": "pre_publish", "old_key_id": 222, "new_key_id": 333}}}}`,
		"zsk signing wrong live":           `{"zones": {"example.com": {"path": "/z", "zsk": {"id": 222, "algorithm": "ED25519"}, "rollover": {"type": "zsk", "state": "signing", "old_key_id": 222, "new_key_id": 333}}}}`,
		"algorithm rollover missing algos": `{"zones": {"example.com": {"path": "/z", "ksk": {"id": 2, "algorithm": "ED25519"}, "zsk": {"id": 4, "algorithm": "ED25519"}, "rollover": {"type": "algorithm", "state": "algo_ds_add_wait", "old_key_id": 1, "new_key_id": 2, "old_zsk_id": 3, "new_zsk_id": 4}}}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeState(t, doc)
			if _, err := LoadState(path); err == nil {
				t.Fatalf("%s must be rejected", name)
			} else if !strings.Contains(err.Error(), "left unchanged") {
				t.Fatalf("error must say the file was left unchanged: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != doc {
				t.Fatal("an invalid state file must never be rewritten")
			}
		})
	}
}

func TestRA6X036_ValidRolloverShapesLoad(t *testing.T) {
	cases := map[string]string{
		"ksk ds_add_wait":     `{"zones": {"example.com": {"path": "/z", "ksk": {"id": 2, "algorithm": "ED25519"}, "rollover": {"type": "ksk", "state": "ds_add_wait", "old_key_id": 1, "new_key_id": 2}}}}`,
		"zsk pre_publish":     `{"zones": {"example.com": {"path": "/z", "zsk": {"id": 222, "algorithm": "ED25519"}, "rollover": {"type": "zsk", "state": "pre_publish", "old_key_id": 222, "new_key_id": 333}}}}`,
		"zsk signing":         `{"zones": {"example.com": {"path": "/z", "zsk": {"id": 333, "algorithm": "ED25519"}, "rollover": {"type": "zsk", "state": "signing", "old_key_id": 222, "new_key_id": 333}}}}`,
		"algorithm":           `{"zones": {"example.com": {"path": "/z", "ksk": {"id": 2, "algorithm": "ECDSAP256SHA256"}, "zsk": {"id": 4, "algorithm": "ECDSAP256SHA256"}, "rollover": {"type": "algorithm", "state": "algo_ds_add_wait", "old_key_id": 1, "new_key_id": 2, "old_zsk_id": 3, "new_zsk_id": 4, "old_algorithm": "ED25519", "new_algorithm": "ECDSAP256SHA256"}}}}`,
		"keyless placeholder": `{"zones": {"example.com": {"path": "/z", "errors": ["init failed"]}}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadState(writeState(t, doc)); err != nil {
				t.Fatalf("%s must load: %v", name, err)
			}
		})
	}
}

func TestRA6X036_ReloadRejectsInvalidDiskStateWithoutMerging(t *testing.T) {
	path := writeState(t, `{"zones": {"good.example": {"path": "/g", "ksk": {"id": 1, "algorithm": "ED25519"}, "zsk": {"id": 2, "algorithm": "ED25519"}}}}`)
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	// The file is replaced by an invalid document (a corrupt CLI write, say).
	bad := `{"zones": {"good.example": null, "evil.example": {"path": "/e"}}}`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := st.ReloadFromDisk(); err == nil {
		t.Fatal("reload must reject an invalid disk state")
	}
	if st.GetZone("good.example") == nil || st.GetZone("evil.example") != nil {
		t.Fatal("in-memory state must be untouched by a rejected reload")
	}
	if got, _ := os.ReadFile(path); string(got) != bad {
		t.Fatal("the invalid file must be left as evidence")
	}
}

func TestRA6X026_ReloadDetectsMissingStateFile(t *testing.T) {
	path := writeState(t, `{"zones": {}}`)
	st, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	err = st.ReloadFromDisk()
	if err == nil || !strings.Contains(err.Error(), "restart the daemon") {
		t.Fatalf("a vanished state file must be an explicit, actionable error, got %v", err)
	}
	// A state that never had a file (fresh start) reloads as a no-op.
	fresh := NewState(filepath.Join(t.TempDir(), "state.json"))
	if err := fresh.ReloadFromDisk(); err != nil {
		t.Fatalf("fresh state with no file must reload as a no-op: %v", err)
	}
	// After a Save the file is expected to exist.
	if err := fresh.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fresh.path); err != nil {
		t.Fatal(err)
	}
	if err := fresh.ReloadFromDisk(); err == nil {
		t.Fatal("a saved-then-removed state file must be detected")
	}
	_ = time.Now()
}
