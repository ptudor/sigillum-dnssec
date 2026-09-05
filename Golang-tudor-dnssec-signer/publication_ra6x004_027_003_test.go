package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// publishedDNSKEYTags parses the signed output's DNSKEY RRset.
func publishedDNSKEYTags(t *testing.T, cfg *config.Config, domain string) map[uint16]bool {
	t.Helper()
	path := filepath.Join(cfg.OutputDir, domain+".zone.signed")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("signed output: %v", err)
	}
	tags := map[uint16]bool{}
	zp := dns.NewZoneParser(strings.NewReader(string(data)), dns.Fqdn(domain), path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if k, ok := rr.(*dns.DNSKEY); ok {
			tags[k.KeyTag()] = true
		}
	}
	return tags
}

// fastRollover shortens the ZSK rollover windows for a test.
func fastRollover(cfg *config.Config) {
	cfg.DNSSEC.RolloverSwitch = config.Duration{Duration: 500 * time.Millisecond}
	cfg.DNSSEC.RolloverPrepublish = config.Duration{Duration: 1 * time.Second}
	cfg.DNSSEC.DNSKEYTtl = 1
}

// --- RA6X-004 ----------------------------------------------------------------

// While the deployment hook keeps failing — for longer than both rollover
// windows — no ZSK phase advances, because nothing was confirmed served. Once
// the hook succeeds, the phase advances only after the cache-safe wait from
// the confirmed publication.
func TestZSKRollover_DoesNotAdvanceOnUnconfirmedPublication(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	fastRollover(cfg)
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "exit 1"} // the reload keeps failing
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	rm := signerpkg.NewRolloverManager(cfg, state)
	zs := state.GetZone(domain)
	zs.ZSK.Expires = time.Now().UTC() // due now → automatic rollover starts on the next check
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover == nil || zs.Rollover.State != statepkg.ZSKRolloverStatePrePublish {
		t.Fatalf("rollover must start in pre_publish, got %+v", zs.Rollover)
	}

	// Cycles over 2.5 s (windows are 0.5 s / 1 s): the file is written every
	// time the rollover forces it, the hook fails every time.
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		d.signAllZones()
		d.hookWG.Wait()
		time.Sleep(300 * time.Millisecond)
	}
	zs = state.GetZone(domain)
	if !zs.PendingPublication || !zs.PublishedAt.IsZero() {
		t.Fatalf("publication must stay unconfirmed while the hook fails (pending=%v published=%v)", zs.PendingPublication, zs.PublishedAt)
	}
	if zs.Rollover == nil || zs.Rollover.State != statepkg.ZSKRolloverStatePrePublish {
		t.Fatalf("no phase may advance on file timestamps alone, got %+v", zs.Rollover)
	}

	// Heal the hook: the pending deployment is retried without re-signing,
	// confirmed asynchronously, and the phase then advances after the floor.
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "exit 0"}
	d.signAllZones()
	d.hookWG.Wait()
	zs = state.GetZone(domain)
	if zs.PendingPublication || zs.PublishedAt.IsZero() {
		t.Fatalf("a successful hook must confirm publication (pending=%v published=%v)", zs.PendingPublication, zs.PublishedAt)
	}
	time.Sleep(1200 * time.Millisecond) // > DNSKEY TTL floor from the confirmed publication
	d.signAllZones()
	d.hookWG.Wait()
	if got := state.GetZone(domain).Rollover.State; got != statepkg.ZSKRolloverStateSigning {
		t.Fatalf("after confirmed publication plus the cache-safe wait the phase must advance, got %q", got)
	}
}

// A pending deployment survives a restart and is retried by the new process.
func TestPendingPublication_RetriedAfterRestart(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "exit 1"}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	d.signAllZones()
	d.hookWG.Wait()
	if !state.GetZone(domain).PendingPublication {
		t.Fatal("a failed hook must leave the zone pending")
	}

	// "Restart": a fresh daemon over the persisted state, hook now healthy and
	// recording its invocations.
	log := filepath.Join(t.TempDir(), "hook.log")
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "echo \"$DNSSEC_DOMAIN\" >> " + log}
	reloaded, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.GetZone(domain).PendingPublication {
		t.Fatal("pending publication must be persisted")
	}
	d2 := NewDaemon(cfg, reloaded)
	d2.signAllZones() // nothing needs signing; the pending deployment is retried
	d2.hookWG.Wait()
	data, _ := os.ReadFile(log)
	if !strings.Contains(string(data), domain) {
		t.Fatalf("the pending deployment must be retried after restart, hook log %q", data)
	}
	zs := reloaded.GetZone(domain)
	if zs.PendingPublication || zs.PublishedAt.IsZero() {
		t.Fatal("the retried hook must confirm publication")
	}
	onDisk, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if onDisk.GetZone(domain).PendingPublication {
		t.Fatal("the confirmation must be persisted")
	}
}

// --- RA6X-027 ----------------------------------------------------------------

// Lowering the DNSKEY TTL right before a rollover must not discard the
// seven-day cache horizon of the RRsets resolvers already hold.
func TestCacheHorizon_SurvivesTTLDecreaseAndRestart(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	fastRollover(cfg)
	cfg.DNSSEC.DNSKEYTtl = 7 * 24 * 3600 // seven-day DNSKEY TTL served for a long time
	s := signerpkg.NewSigner(cfg, state)
	if err := s.SignZone(domain); err != nil {
		t.Fatal(err)
	}
	zs := state.GetZone(domain)
	if zs.ServedDNSKEYTTL != 7*24*3600 {
		t.Fatalf("immediate mode must confirm the served TTL, got %d", zs.ServedDNSKEYTTL)
	}

	// Lower the TTL and re-sign immediately.
	cfg.DNSSEC.DNSKEYTtl = 3600
	state.Mutate(func() { zs.ForceResign = true })
	if err := s.SignZone(domain); err != nil {
		t.Fatal(err)
	}
	sixDays := time.Now().Add(6 * 24 * time.Hour)
	if zs.PublishedDNSKEYTTL != 3600 {
		t.Fatalf("the configured TTL must be honoured on the wire, got %d", zs.PublishedDNSKEYTTL)
	}
	if zs.DNSKEYCacheHorizon.Before(sixDays) {
		t.Fatalf("the seven-day horizon must survive the TTL decrease, got %v", zs.DNSKEYCacheHorizon)
	}

	// Repeated increases/decreases only ever raise the horizon.
	for _, ttl := range []uint32{2 * 24 * 3600, 60, 5 * 24 * 3600, 30} {
		cfg.DNSSEC.DNSKEYTtl = ttl
		state.Mutate(func() { zs.ForceResign = true })
		if err := s.SignZone(domain); err != nil {
			t.Fatal(err)
		}
		if zs.DNSKEYCacheHorizon.Before(sixDays) {
			t.Fatalf("horizon lowered by a TTL change to %d: %v", ttl, zs.DNSKEYCacheHorizon)
		}
	}

	// Start a rollover now: the phase must wait for the old horizon, not the
	// one-hour floor.
	rm := signerpkg.NewRolloverManager(cfg, state)
	zs.ZSK.Expires = time.Now().UTC()
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if err := s.SignZone(domain); err != nil { // pre-published set, confirmed immediately
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond) // past the switch window
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	zs = state.GetZone(domain)
	if zs.Rollover == nil || zs.Rollover.State != statepkg.ZSKRolloverStatePrePublish {
		t.Fatalf("the phase must not advance while old DNSKEY RRsets may still be cached, got %+v", zs.Rollover)
	}
	if zs.Rollover.PhaseHorizon.Before(sixDays) {
		t.Fatalf("the phase horizon must carry the seven-day cache lifetime, got %v", zs.Rollover.PhaseHorizon)
	}

	// Restart: horizons are persisted.
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	rz := reloaded.GetZone(domain)
	if !rz.DNSKEYCacheHorizon.Equal(zs.DNSKEYCacheHorizon) || !rz.Rollover.PhaseHorizon.Equal(zs.Rollover.PhaseHorizon) {
		t.Fatal("cache horizons must survive a restart")
	}
	if err := signerpkg.NewRolloverManager(cfg, reloaded).CheckZSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if reloaded.GetZone(domain).Rollover.State != statepkg.ZSKRolloverStatePrePublish {
		t.Fatal("the persisted wait must still hold after restart")
	}
}

// --- RA6X-003 ----------------------------------------------------------------

type fakeParentProbe struct {
	present, absent bool
	ttl             uint32
}

func (f fakeParentProbe) ProbeParentDS(domain string, ksks []*dns.DNSKEY) (signerpkg.ParentDSObservation, error) {
	obs := signerpkg.ParentDSObservation{PresentOnAll: map[uint16]bool{}, AbsentOnAll: map[uint16]bool{}, TTL: f.ttl, Servers: []string{"parent-a", "parent-b"}}
	for _, k := range ksks {
		obs.PresentOnAll[k.KeyTag()] = f.present
		obs.AbsentOnAll[k.KeyTag()] = f.absent
	}
	return obs, nil
}

// Two resolver caches are modelled: cache A fetched the old-only DS set just
// before the new DS appeared and holds it for the parent's DS TTL; cache B
// fetches fresh. Both validate continuously only if the old KSK stays in the
// served DNSKEY RRset until cache A's DS expires — and the wait survives a
// restart and a TTL decrease.
func TestKSKRollover_RetiresOnlyAfterParentDSTTL(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	s := signerpkg.NewSigner(cfg, state)
	if err := s.SignZone(domain); err != nil {
		t.Fatal(err)
	}
	oldKSK := state.GetZone(domain).KSK.ID
	rm := signerpkg.NewRolloverManager(cfg, state)
	if err := rm.StartKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	newKSK := state.GetZone(domain).Rollover.NewKeyID
	if err := s.SignZone(domain); err != nil {
		t.Fatal(err)
	}

	// Cache A: old-only DS fetched now, DS TTL 2 s. The new DS is observed at
	// every parent server now.
	const dsTTL = 2
	observed := time.Now().UTC()
	cacheAExpires := observed.Add(dsTTL * time.Second)
	if err := rm.CompleteKSKRollover(domain, observed, dsTTL); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	// A TTL decrease in the configuration cannot shorten the persisted wait.
	cfg.DNSSEC.ParentDSTTL = config.Duration{Duration: time.Millisecond}

	// Restart in the middle of the wait.
	reloaded, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	rm2 := signerpkg.NewRolloverManager(cfg, reloaded)
	s2 := signerpkg.NewSigner(cfg, reloaded)
	for time.Now().Before(cacheAExpires.Add(-300 * time.Millisecond)) {
		if err := rm2.CheckKSKRollover(domain); err != nil {
			t.Fatal(err)
		}
		if err := s2.SignZone(domain); err != nil {
			t.Fatal(err)
		}
		tags := publishedDNSKEYTags(t, cfg, domain)
		if !tags[oldKSK] || !tags[newKSK] {
			t.Fatalf("while cache A may hold the old-only DS, both KSKs must be served; got %v", tags)
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(time.Until(cacheAExpires) + 100*time.Millisecond)
	if err := rm2.CheckKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.GetZone(domain).Rollover.State; got != statepkg.KSKRolloverStateRetiring {
		t.Fatalf("after the parent DS TTL the old KSK must be retired, got %q", got)
	}
	if err := s2.SignZone(domain); err != nil {
		t.Fatal(err)
	}
	tags := publishedDNSKEYTags(t, cfg, domain)
	if tags[oldKSK] || !tags[newKSK] {
		t.Fatalf("retired zone must serve only the new KSK, got %v", tags)
	}
	if err := rm2.CheckKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if reloaded.GetZone(domain).Rollover != nil {
		t.Fatal("the rollover must end once the retiring generation is served")
	}
}

// Algorithm rollover: the old-algorithm keys and signatures stay until the old
// DS is gone from every parent server plus a DS TTL; the old DS removal is
// only observed through the all-parents probe.
func TestAlgorithmRollover_RetiresOldAlgorithmAfterOldDSGone(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	s := signerpkg.NewSigner(cfg, state)
	if err := s.SignZone(domain); err != nil {
		t.Fatal(err)
	}
	oldKSK := state.GetZone(domain).KSK.ID
	rm := signerpkg.NewRolloverManager(cfg, state)
	if err := rm.StartAlgorithmRollover(domain, "ECDSAP256SHA256"); err != nil {
		t.Fatal(err)
	}
	newKSK := state.GetZone(domain).Rollover.NewKeyID
	if err := s.SignZone(domain); err != nil {
		t.Fatal(err)
	}
	if err := rm.CompleteAlgorithmRollover(domain, time.Now().Add(-time.Hour), 1); err != nil {
		t.Fatal(err)
	}
	if err := rm.CheckAlgorithmRollover(domain); err != nil {
		t.Fatal(err)
	}
	zs := state.GetZone(domain)
	if zs.Rollover.State != statepkg.AlgoRolloverStateOldDSRemoval || !zs.Rollover.NeedsOperator() {
		t.Fatalf("after the DS TTL the operator must remove the old DS, got %+v", zs.Rollover)
	}

	// Old DS still present at one parent → nothing retires.
	rm.SetParentDSProbe(fakeParentProbe{present: false, absent: false, ttl: 1})
	if err := rm.CheckAlgorithmRollover(domain); err != nil {
		t.Fatal(err)
	}
	if err := s.SignZone(domain); err != nil {
		t.Fatal(err)
	}
	if tags := publishedDNSKEYTags(t, cfg, domain); !tags[oldKSK] || !tags[newKSK] {
		t.Fatalf("both algorithms must stay published while the old DS may be cached, got %v", tags)
	}
	if !zs.Rollover.OldDSRemovedAt.IsZero() {
		t.Fatal("old DS removal must not be recorded while a parent still serves it")
	}

	// Old DS gone everywhere: one more DS TTL, then retirement.
	rm.SetParentDSProbe(fakeParentProbe{absent: true, ttl: 1})
	if err := rm.CheckAlgorithmRollover(domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover.OldDSRemovedAt.IsZero() {
		t.Fatal("old DS removal must be recorded once every parent server lacks it")
	}
	if err := rm.CheckAlgorithmRollover(domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover.State != statepkg.AlgoRolloverStateOldDSRemoval {
		t.Fatal("the old algorithm must not retire before the DS TTL elapses")
	}
	time.Sleep(1100 * time.Millisecond)
	if err := rm.CheckAlgorithmRollover(domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover.State != statepkg.AlgoRolloverStateRetiring {
		t.Fatalf("after the DS TTL the old algorithm must retire, got %q", zs.Rollover.State)
	}
	if err := s.SignZone(domain); err != nil {
		t.Fatal(err)
	}
	if tags := publishedDNSKEYTags(t, cfg, domain); tags[oldKSK] || !tags[newKSK] {
		t.Fatalf("retired zone must serve only the new algorithm, got %v", tags)
	}
	if err := rm.CheckAlgorithmRollover(domain); err != nil {
		t.Fatal(err)
	}
	if state.GetZone(domain).Rollover != nil {
		t.Fatal("the rollover must end once the retiring generation is served")
	}
}

// `rollover complete` refuses while the phase is automatic, and --force starts
// the wait from now with the configured fallback DS TTL.
func TestRolloverComplete_AutomaticPhasesRefuseAndForceUsesFallback(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	cfg.DNSSEC.ParentDSTTL = config.Duration{Duration: 90 * time.Minute}
	rm := signerpkg.NewRolloverManager(cfg, state)
	if err := rm.StartKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if err := rm.CompleteKSKRollover(domain, time.Now(), 0); err != nil {
		t.Fatal(err)
	}
	r := state.GetZone(domain).Rollover
	if r.ParentDSTTL != 90*60 {
		t.Fatalf("an unobservable DS TTL must fall back to parent_ds_ttl, got %d", r.ParentDSTTL)
	}
	if err := rm.CompleteKSKRollover(domain, time.Now(), 1); err == nil || !strings.Contains(err.Error(), "automatic") {
		t.Fatalf("completing again during the automatic phase must be refused, got %v", err)
	}
	if got := state.GetZone(domain).Status(); got != "warning" {
		t.Fatalf("an automatic wait is not action_required, got %q", got)
	}
}
