package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

func hasErrorPrefix(errs []string, prefix string) bool {
	for _, e := range errs {
		if strings.HasPrefix(e, prefix+": ") {
			return true
		}
	}
	return false
}

// --- RA6X-033 ----------------------------------------------------------------

// A configured zone with corrupt key files and no state entry must appear in
// status with its initialization error, count as a failed signing operation,
// and make readiness fail; repairing the keys clears it on the next cycle.
func TestInitFailure_VisibleInStatusMetricsAndReadiness(t *testing.T) {
	dir := t.TempDir()
	cfg := dnssectest.Config(t, dir)
	domain := "broken.example"
	zonePath := filepath.Join(dir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent(domain)), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}
	for _, d := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := signerpkg.EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	// Corrupt existing key pair: present but unusable → recovery refuses.
	for _, name := range []string{domain + ".ksk.key", domain + ".ksk.private"} {
		if err := os.WriteFile(filepath.Join(cfg.KeysDir(), name), []byte("garbage\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	state := statepkg.NewState(cfg.StatePath())
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	d := NewDaemon(cfg, state)

	// Before the first cycle: configured but absent from state is already an
	// error in status and readiness, not an invisible zone.
	out := buildStatusOutput(state, configuredZones(cfg)...)
	if out.Summary.Total != 1 || out.Summary.Errors != 1 || out.Zones[domain] == nil {
		t.Fatalf("a configured, uninitialized zone must be counted as an error: %+v", out.Summary)
	}
	if problems := unreadyZones(cfg, state); len(problems) != 1 {
		t.Fatalf("readiness must report the uninitialized zone, got %v", problems)
	}

	d.signAllZones()
	d.hookWG.Wait()
	zs := state.GetZone(domain)
	if zs == nil || !hasErrorPrefix(zs.Errors, statepkg.OpInit) {
		t.Fatalf("the failed initialization must leave an error-bearing placeholder, got %+v", zs)
	}
	handler := NewWebServer(d).Handler
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rr.Code != http.StatusServiceUnavailable || !strings.Contains(rr.Body.String(), domain) {
		t.Fatalf("/health must be 503 naming the zone, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/healthz must be 503, got %d", rr.Code)
	}
	if !strings.Contains(metricsBody(t), `signing_operations_total{domain="`+domain+`",status="failure"} 1`) {
		t.Fatal("the failed initialization must be counted as a failed signing operation")
	}

	// Repair: remove the corrupt pair so fresh keys are generated.
	for _, name := range []string{domain + ".ksk.key", domain + ".ksk.private"} {
		if err := os.Remove(filepath.Join(cfg.KeysDir(), name)); err != nil {
			t.Fatal(err)
		}
	}
	d.signAllZones()
	d.hookWG.Wait()
	zs = state.GetZone(domain)
	if zs.KSK == nil || hasErrorPrefix(zs.Errors, statepkg.OpInit) || zs.LastSigned.IsZero() {
		t.Fatalf("a later cycle must initialize and sign the zone and clear the error, got %+v", zs)
	}
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("/healthz must recover, got %d", rr.Code)
	}
}

// metricsBody scrapes the process-wide Prometheus registry the daemon exposes
// on its /metrics endpoint.
func metricsBody(t *testing.T) string {
	t.Helper()
	rr := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rr.Body.String()
}

// --- RA6X-048 ----------------------------------------------------------------

// A one-shot `sign` whose rollover step fails exits non-zero and persists the
// rollover error on the zone, while the zones themselves were signed.
func TestCLISign_RolloverFailureIsPersistedAndFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("relies on filesystem permissions; not meaningful as root")
	}
	z := newCLIZones(t, false, "roll.example")
	// Make the ZSK due so the automatic rollover starts, then make its backup
	// impossible by removing write permission from the keys dir.
	zs := z.state.GetZone("roll.example")
	zs.ZSK.Expires = time.Now().UTC().Add(-time.Hour)
	if err := z.state.Save(); err != nil {
		t.Fatal(err)
	}
	// Signing must still succeed: give the output dir first, then lock the keys.
	if err := os.Chmod(z.cfg.KeysDir(), 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(z.cfg.KeysDir(), 0700) })

	err := runSign(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "rollover failed") {
		t.Fatalf("sign must exit non-zero on a rollover failure, got %v", err)
	}
	reloaded, lerr := statepkg.LoadState(z.cfg.StatePath())
	if lerr != nil {
		t.Fatal(lerr)
	}
	if !hasErrorPrefix(reloaded.GetZone("roll.example").Errors, statepkg.OpRollover) {
		t.Fatalf("the rollover failure must be persisted on the zone, got %v", reloaded.GetZone("roll.example").Errors)
	}
	if _, serr := os.Stat(z.signedPath("roll.example")); serr != nil {
		t.Fatal("the zone must still have been signed")
	}
}

// A seeded signing error is cleared by a successful `resign`; an unrelated
// registrar error survives; a failing `resign` records its own error while
// keeping the last good output and the unrelated error.
func TestCLIResign_ErrorBookkeeping(t *testing.T) {
	z := newCLIZones(t, false, "fix.example")
	zs := z.state.GetZone("fix.example")
	z.state.Mutate(func() {
		zs.SetOperationError(statepkg.OpSigning, "earlier failure")
		zs.SetOperationError(statepkg.OpRegistrar, "registrar unreachable")
	})
	if err := z.state.Save(); err != nil {
		t.Fatal(err)
	}

	if err := runResign(nil, []string{"fix.example"}); err != nil {
		t.Fatalf("resign after repair: %v", err)
	}
	reloaded, err := statepkg.LoadState(z.cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	errs := reloaded.GetZone("fix.example").Errors
	if hasErrorPrefix(errs, statepkg.OpSigning) {
		t.Fatalf("a successful resign must clear the signing error, got %v", errs)
	}
	if !hasErrorPrefix(errs, statepkg.OpRegistrar) {
		t.Fatalf("an unrelated registrar error must be retained, got %v", errs)
	}
	good, err := os.ReadFile(z.signedPath("fix.example"))
	if err != nil {
		t.Fatal(err)
	}

	// Now break the source and resign: the failure is recorded, the last good
	// output and the unrelated error stay.
	if err := os.WriteFile(z.zones["fix.example"], []byte("not a zone\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runResign(nil, []string{"fix.example"}); err == nil {
		t.Fatal("resign of an invalid zone must fail")
	}
	reloaded, err = statepkg.LoadState(z.cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	errs = reloaded.GetZone("fix.example").Errors
	if !hasErrorPrefix(errs, statepkg.OpSigning) || !hasErrorPrefix(errs, statepkg.OpRegistrar) {
		t.Fatalf("the new signing error must be recorded beside the unrelated one, got %v", errs)
	}
	if now, _ := os.ReadFile(z.signedPath("fix.example")); !bytes.Equal(good, now) {
		t.Fatal("the last good output must be preserved")
	}
	if reloaded.GetZone("fix.example").Status() != "error" {
		t.Fatal("status must reflect the recorded error")
	}
}
