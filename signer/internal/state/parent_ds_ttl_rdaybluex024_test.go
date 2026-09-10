package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RDAYBLUEX-024: a persisted parent DS TTL beyond the DNS TTL range is a
// wrapped/corrupt value; the document is refused for repair. Zero stays
// loadable (it means the conservative default at the gates).
func TestRDAYBLUEX024_CorruptPersistedParentDSTTLRejected(t *testing.T) {
	dir := t.TempDir()
	write := func(ttl string) (*State, error) {
		p := filepath.Join(dir, "state.json")
		doc := `{"zones":{"a.":{"path":"/z","serial":1,"last_signed":"2024-01-01T00:00:00Z","signatures_expire":"2024-01-15T00:00:00Z",
"ksk":{"id":2,"algorithm":"ED25519","created":"2024-01-01T00:00:00Z","expires":"2029-01-01T00:00:00Z"},
"zsk":{"id":3,"algorithm":"ED25519","created":"2024-01-01T00:00:00Z","expires":"2024-04-01T00:00:00Z"},
"rollover":{"type":"ksk","state":"ds_propagation_wait","old_key_id":1,"new_key_id":2,"started":"2024-01-01T00:00:00Z","parent_ds_ttl":` + ttl + `,"action":"x"}}}}`
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadState(p)
	}
	if _, err := write("0"); err != nil {
		t.Fatalf("a legacy zero TTL must load: %v", err)
	}
	if _, err := write("86400"); err != nil {
		t.Fatalf("a normal TTL must load: %v", err)
	}
	if _, err := write("2147483647"); err != nil {
		t.Fatalf("the maximum DNS TTL must load: %v", err)
	}
	if _, err := write("2147483648"); err == nil || !strings.Contains(err.Error(), "parent_ds_ttl") {
		t.Fatalf("a TTL beyond the DNS range must be refused for repair, got %v", err)
	}
	if _, err := write("4294967295"); err == nil {
		t.Fatal("a wrapped TTL must be refused")
	}
}
