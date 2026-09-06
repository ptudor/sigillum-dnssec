package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	"github.com/ptudor/sigillum-dnssec/signer/internal/registrar"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// fakeRegistrar is a Dynadot-shaped DS store whose DELETE applies and then
// drops the connection, and whose restore PUTs fail until healed.
type fakeRegistrar struct {
	mu      sync.Mutex
	records map[string]map[string]string // key_tag → fields
	healed  bool
	puts    int
}

func (f *fakeRegistrar) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodPut:
		f.puts++
		if !f.healed && f.puts >= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"code":500,"message":"down"}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var b map[string]any
		_ = json.Unmarshal(body, &b)
		tag := fmt.Sprintf("%v", b["key_tag"])
		f.records[tag] = map[string]string{
			"algorithm": fmt.Sprintf("%v", b["algorithm"]), "digest_type": fmt.Sprintf("%v", b["digest_type"]), "digest": fmt.Sprintf("%v", b["digest"]),
		}
		io.WriteString(w, `{"code":200,"message":"Success"}`)
	case http.MethodDelete:
		f.records = map[string]map[string]string{}
		panic(http.ErrAbortHandler)
	case http.MethodGet:
		var items []string
		for tag, fields := range f.records {
			items = append(items, fmt.Sprintf(`{"key_tag":%s,"algorithm":%q,"digest_type":%q,"digest":%q}`, tag, fields["algorithm"], fields["digest_type"], fields["digest"]))
		}
		io.WriteString(w, `{"code":200,"message":"Success","data":{"dnssec_info_list":[`+strings.Join(items, ",")+`]}}`)
	}
}

// A lost DELETE response with a failing restore must leave a persisted
// emergency warning; a later push from a fresh process restores the DS set and
// clears the warning.
func TestRegistrarPush_RecoveryAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	local := dnssectest.Config(t, dir)
	domain := "reg.example"
	for _, d := range []string{local.KeysDir(), local.OutputDir} {
		if err := signerpkg.EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	kg := signerpkg.NewKeyGenerator(local)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zonePath := filepath.Join(dir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent(domain)), 0644); err != nil {
		t.Fatal(err)
	}
	st := statepkg.NewState(local.StatePath())
	st.SetZone(domain, &statepkg.ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	fake := &fakeRegistrar{records: map[string]map[string]string{"9": {"algorithm": "15", "digest_type": "2", "digest": "aa"}}}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	defer srv.Close()

	cfgPath := filepath.Join(dir, "config.toml")
	content := fmt.Sprintf(`output_dir = %q
data_dir = %q

[registrar.dynadot]
enabled = true
api_key = "test-key"
api_secret = "test-secret"
base_url = %q
timeout = "5s"

[zones.%q]
path = %q
registrar = "dynadot"
`, local.OutputDir, dir, srv.URL, domain, zonePath)
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	orig := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = orig })

	// First process: the clear applies, the response is lost, the restore fails.
	err = RunRegistrarPush(nil, []string{domain})
	if !errors.Is(err, registrar.ErrRegistrarDSEmpty) {
		t.Fatalf("push must report the emergency outcome, got %v", err)
	}
	reloaded, err := statepkg.LoadState(local.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	zs := reloaded.GetZoneCopy(domain)
	sticky := false
	for _, w := range zs.Warnings {
		if strings.HasPrefix(w, "URGENT:") {
			sticky = true
		}
	}
	if !sticky {
		t.Fatalf("an emergency outcome must persist a sticky remediation warning, got %v", zs.Warnings)
	}

	// Restart: a new process, registrar healed. The push restores and verifies.
	fake.mu.Lock()
	fake.healed = true
	fake.mu.Unlock()
	if err := RunRegistrarPush(nil, []string{domain}); err != nil {
		t.Fatalf("push after restart must restore the DS set: %v", err)
	}
	fake.mu.Lock()
	_, has := fake.records[fmt.Sprintf("%d", ksk.ID)]
	_, old := fake.records["9"]
	fake.mu.Unlock()
	if !has || old {
		t.Fatalf("registrar must hold exactly the live KSK's DS, has %v", fake.records)
	}
	reloaded, err = statepkg.LoadState(local.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range reloaded.GetZoneCopy(domain).Warnings {
		if strings.HasPrefix(w, "URGENT:") {
			t.Fatalf("the sticky warning must be cleared after a verified push, got %v", reloaded.GetZoneCopy(domain).Warnings)
		}
	}
}
