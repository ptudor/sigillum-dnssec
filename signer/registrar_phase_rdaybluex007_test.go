//go:build !windows

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-007 end to end against a Dynadot-shaped fake registrar: KSK
// completion replaces with the new-only set, algorithm completion initially
// retains both, the later automatic transition replaces with new-only
// exactly once, a transient failure is retried without retiring keys, and
// `registrar push` never re-adds the old DS in a removal/retirement phase.

// wellBehavedRegistrar stores DS records by key tag; PUT upserts, DELETE
// wipes, GET lists. failPuts makes every PUT fail with 500.
type wellBehavedRegistrar struct {
	mu       sync.Mutex
	records  map[string]map[string]string
	puts     int
	deletes  int
	failPuts bool
}

func (f *wellBehavedRegistrar) handler(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodPut:
		f.puts++
		if f.failPuts {
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
		f.deletes++
		f.records = map[string]map[string]string{}
		io.WriteString(w, `{"code":200,"message":"Success"}`)
	case http.MethodGet:
		var items []string
		for tag, fields := range f.records {
			items = append(items, fmt.Sprintf(`{"key_tag":%s,"algorithm":%q,"digest_type":%q,"digest":%q}`, tag, fields["algorithm"], fields["digest_type"], fields["digest"]))
		}
		io.WriteString(w, `{"code":200,"message":"Success","data":{"dnssec_info_list":[`+strings.Join(items, ",")+`]}}`)
	}
}

func (f *wellBehavedRegistrar) tags() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for tag := range f.records {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func (f *wellBehavedRegistrar) counts() (puts, deletes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.puts, f.deletes
}

func (f *wellBehavedRegistrar) setFailPuts(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failPuts = v
}

// registrarLab is a managed zone bound to the fake registrar with
// auto_publish on, loaded from a real config file (so `registrar push` can
// run against the same configuration).
type registrarLab struct {
	cfg    *config.Config
	state  *statepkg.State
	domain string
	fake   *wellBehavedRegistrar
}

func newRegistrarLab(t *testing.T) *registrarLab {
	t.Helper()
	dir := t.TempDir()
	fake := &wellBehavedRegistrar{records: map[string]map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(fake.handler))
	t.Cleanup(srv.Close)
	domain := "auto.example"
	zonePath := filepath.Join(dir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent(domain)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.toml")
	content := fmt.Sprintf(`output_dir = %q
data_dir = %q

[dnssec]
parent_ds_ttl = "1s"

[registrar.dynadot]
enabled = true
api_key = "test-key"
api_secret = "test-secret"
base_url = %q
timeout = "5s"
auto_publish = true

[zones.%q]
path = %q
registrar = "dynadot"
`, filepath.Join(dir, "signed"), dir, srv.URL, domain, zonePath)
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = orig })
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := signerpkg.EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	kg := signerpkg.NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	state := statepkg.NewState(cfg.StatePath())
	state.SetZone(domain, &statepkg.ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	return &registrarLab{cfg: cfg, state: state, domain: domain, fake: fake}
}

func tagStrings(ids ...uint16) []string {
	var out []string
	for _, id := range ids {
		out = append(out, fmt.Sprintf("%d", id))
	}
	sort.Strings(out)
	return out
}

func TestRDAYBLUEX007_KSKCompletionReplacesWithNewOnly(t *testing.T) {
	lab := newRegistrarLab(t)
	oldTag := lab.state.GetZone(lab.domain).KSK.ID
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "add")
	rm := newRolloverManager(lab.cfg, lab.state)
	if err := rm.StartKSKRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "rollover_start")
	newTag := lab.state.GetZone(lab.domain).Rollover.NewKeyID
	if got := lab.fake.tags(); strings.Join(got, ",") != strings.Join(tagStrings(oldTag, newTag), ",") {
		t.Fatalf("rollover start publishes old+new additively, got %v", got)
	}
	if err := rm.CompleteKSKRollover(lab.domain, time.Now(), 60); err != nil {
		t.Fatal(err)
	}
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "rollover_complete")
	if got := lab.fake.tags(); strings.Join(got, ",") != fmt.Sprintf("%d", newTag) {
		t.Fatalf("KSK completion must leave only the new DS at the registrar, got %v (old %d new %d)", got, oldTag, newTag)
	}
	// A later explicit push in the propagation/retirement phases never
	// resurrects the old DS.
	lab.fake.mu.Lock()
	lab.fake.records[fmt.Sprintf("%d", oldTag)] = map[string]string{"algorithm": "15", "digest_type": "2", "digest": "aa"}
	lab.fake.mu.Unlock()
	if err := RunRegistrarPush(nil, []string{lab.domain}); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != fmt.Sprintf("%d", newTag) {
		t.Fatalf("push during ds_propagation_wait must not re-add the old DS, got %v", got)
	}
	zs := lab.state.GetZone(lab.domain)
	lab.state.Mutate(func() { zs.Rollover.State = statepkg.KSKRolloverStateRetiring })
	if err := lab.state.Save(); err != nil {
		t.Fatal(err)
	}
	if err := RunRegistrarPush(nil, []string{lab.domain}); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != fmt.Sprintf("%d", newTag) {
		t.Fatalf("push during retiring must keep new-only, got %v", got)
	}
}

func TestRDAYBLUEX007_AlgorithmRolloverReplacesNewOnlyExactlyOnceAtSafeTransition(t *testing.T) {
	lab := newRegistrarLab(t)
	oldTag := lab.state.GetZone(lab.domain).KSK.ID
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "add")
	rm := newRolloverManager(lab.cfg, lab.state)
	rm.SetParentDSProbe(fakeParentProbe{present: false, absent: false, ttl: 1}) // old DS still visible at a parent
	if err := rm.StartAlgorithmRollover(lab.domain, "ECDSAP256SHA256"); err != nil {
		t.Fatal(err)
	}
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "rollover_start")
	newTag := lab.state.GetZone(lab.domain).Rollover.NewKeyID
	if got := lab.fake.tags(); strings.Join(got, ",") != strings.Join(tagStrings(oldTag, newTag), ",") {
		t.Fatalf("algorithm rollover start publishes both, got %v", got)
	}

	// Completion enters the DS-propagation wait: both DS are retained and
	// nothing is deleted.
	if err := rm.CompleteAlgorithmRollover(lab.domain, time.Now().Add(-2*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "rollover_complete")
	if got := lab.fake.tags(); strings.Join(got, ",") != strings.Join(tagStrings(oldTag, newTag), ",") {
		t.Fatalf("algorithm completion must retain both DS, got %v", got)
	}
	if _, deletes := lab.fake.counts(); deletes != 0 {
		t.Fatalf("no destructive replace may happen at algorithm completion, got %d DELETEs", deletes)
	}

	// The DS TTL elapsed: the automatic transition into old-DS-removal
	// replaces with the new-only set — exactly once, persisted as pushed.
	if err := rm.CheckAlgorithmRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	zs := lab.state.GetZone(lab.domain)
	if zs.Rollover.State != statepkg.AlgoRolloverStateOldDSRemoval {
		t.Fatalf("expected the old-DS-removal phase, got %q", zs.Rollover.State)
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != fmt.Sprintf("%d", newTag) {
		t.Fatalf("the transition must replace with the new-only set, got %v", got)
	}
	if zs.Rollover.DSRemovalPushedAt.IsZero() {
		t.Fatal("the successful update must be recorded")
	}
	_, deletes := lab.fake.counts()
	if deletes != 1 {
		t.Fatalf("exactly one replace expected, got %d DELETEs", deletes)
	}
	disk, _ := statepkg.LoadState(lab.cfg.StatePath())
	if disk.GetZone(lab.domain).Rollover.DSRemovalPushedAt.IsZero() {
		t.Fatal("the marker must be persisted")
	}

	// Further checks (old DS still cached at a parent) do not repeat it; a
	// restart (fresh manager over the persisted state) does not either.
	for i := 0; i < 3; i++ {
		if err := rm.CheckAlgorithmRollover(lab.domain); err != nil {
			t.Fatal(err)
		}
	}
	rm2 := newRolloverManager(lab.cfg, disk)
	rm2.SetParentDSProbe(fakeParentProbe{present: false, absent: false, ttl: 1})
	if err := rm2.CheckAlgorithmRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if _, deletes := lab.fake.counts(); deletes != 1 {
		t.Fatalf("the new-only replace must not be repeated, got %d DELETEs", deletes)
	}
	if zs.Rollover.State != statepkg.AlgoRolloverStateOldDSRemoval || zs.KSK.ID != newTag {
		t.Fatalf("no key may be retired while the old DS is still served: %+v", zs.Rollover)
	}

	// An explicit push in this phase keeps new-only even if the old DS crept back.
	lab.fake.mu.Lock()
	lab.fake.records[fmt.Sprintf("%d", oldTag)] = map[string]string{"algorithm": "15", "digest_type": "2", "digest": "aa"}
	lab.fake.mu.Unlock()
	if err := RunRegistrarPush(nil, []string{lab.domain}); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != fmt.Sprintf("%d", newTag) {
		t.Fatalf("push during old-DS-removal must not re-add the old DS, got %v", got)
	}
}

func TestRDAYBLUEX007_TransientRegistrarFailureRetriesWithoutRetiring(t *testing.T) {
	lab := newRegistrarLab(t)
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "add")
	rm := newRolloverManager(lab.cfg, lab.state)
	rm.SetParentDSProbe(fakeParentProbe{present: false, absent: false, ttl: 1})
	if err := rm.StartAlgorithmRollover(lab.domain, "ECDSAP256SHA256"); err != nil {
		t.Fatal(err)
	}
	MaybeAutoPublishDS(lab.cfg, lab.state, lab.domain, "rollover_start")
	newTag := lab.state.GetZone(lab.domain).Rollover.NewKeyID
	if err := rm.CompleteAlgorithmRollover(lab.domain, time.Now().Add(-2*time.Second), 1); err != nil {
		t.Fatal(err)
	}
	both := lab.fake.tags()
	forceBefore := lab.state.GetZone(lab.domain).ForceResign

	lab.fake.setFailPuts(true)
	if err := rm.CheckAlgorithmRollover(lab.domain); err != nil {
		t.Fatalf("a registrar failure is a warning, not a rollover error: %v", err)
	}
	zs := lab.state.GetZone(lab.domain)
	if zs.Rollover.State != statepkg.AlgoRolloverStateOldDSRemoval {
		t.Fatalf("the phase transition itself stands, got %q", zs.Rollover.State)
	}
	if !zs.Rollover.DSRemovalPushedAt.IsZero() {
		t.Fatal("a failed update must not be recorded as pushed")
	}
	if !strings.Contains(strings.Join(zs.Warnings, "\n"), "registrar auto-publish failed") {
		t.Fatalf("the failure must be a visible zone warning: %v", zs.Warnings)
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != strings.Join(both, ",") {
		t.Fatalf("PUT-first: a failed replace leaves the prior DS set intact, got %v", got)
	}
	if zs.KSK.ID != newTag || zs.ForceResign != forceBefore {
		t.Fatal("no key may be retired or re-sign forced on a failed registrar update")
	}
	// Retried on the next check while still failing: still not pushed.
	if err := rm.CheckAlgorithmRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if !zs.Rollover.DSRemovalPushedAt.IsZero() {
		t.Fatal("still failing: not pushed")
	}
	// Healed: the next check replaces once.
	lab.fake.setFailPuts(false)
	if err := rm.CheckAlgorithmRollover(lab.domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover.DSRemovalPushedAt.IsZero() {
		t.Fatal("the healed update must be recorded")
	}
	if got := lab.fake.tags(); strings.Join(got, ",") != fmt.Sprintf("%d", newTag) {
		t.Fatalf("after healing the registrar holds new-only, got %v", got)
	}
	if _, deletes := lab.fake.counts(); deletes != 1 {
		t.Fatalf("exactly one replace after healing, got %d", deletes)
	}
}
