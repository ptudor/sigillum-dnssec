package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// --- fixtures ---------------------------------------------------------------

// txZone is a signable zone with generated keys whose state has been saved to
// disk, so a test can "restart" by reloading the state file.
type txZone struct {
	cfg    *config.Config
	state  *statepkg.State
	domain string
	oldKSK uint16
	oldZSK uint16
}

func newTxZone(t *testing.T) *txZone {
	t.Helper()
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	domain := "tx.example.com"
	zone := `$ORIGIN tx.example.com.
$TTL 3600
@	IN	SOA	ns1.tx.example.com. admin.tx.example.com. 2024011501 3600 1800 604800 86400
@	IN	NS	ns1.tx.example.com.
ns1	IN	A	192.0.2.1
www	IN	A	192.0.2.20
`
	zonePath := filepath.Join(dataDir, "tx.zone")
	if err := os.WriteFile(zonePath, []byte(zone), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}
	for _, d := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	kg := NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	st := statepkg.NewState(cfg.StatePath())
	st.SetZone(domain, &statepkg.ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})
	if err := NewSigner(cfg, st).SignZone(domain); err != nil {
		t.Fatalf("initial sign: %v", err)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	return &txZone{cfg: cfg, state: st, domain: domain, oldKSK: ksk.ID, oldZSK: zsk.ID}
}

// restart reloads the persisted state as a fresh process would.
func (z *txZone) restart(t *testing.T) *statepkg.State {
	t.Helper()
	st, err := statepkg.LoadState(z.cfg.StatePath())
	if err != nil {
		t.Fatalf("reloading state: %v", err)
	}
	return st
}

func (z *txZone) signedPath() string {
	return filepath.Join(z.cfg.OutputDir, z.domain+".zone.signed")
}

// published parses the signed zone and returns the DNSKEY tags (tag→flags),
// the tags signing DNSKEY, and the tags signing every other RRset.
func (z *txZone) published(t *testing.T) (keys map[uint16]uint16, dnskeySigners, dataSigners map[uint16]int) {
	t.Helper()
	data, err := os.ReadFile(z.signedPath())
	if err != nil {
		t.Fatalf("reading signed zone: %v", err)
	}
	keys = map[uint16]uint16{}
	dnskeySigners = map[uint16]int{}
	dataSigners = map[uint16]int{}
	zp := dns.NewZoneParser(strings.NewReader(string(data)), dns.Fqdn(z.domain), z.signedPath())
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		switch r := rr.(type) {
		case *dns.DNSKEY:
			keys[r.KeyTag()] = r.Flags
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeDNSKEY {
				dnskeySigners[r.KeyTag]++
			} else {
				dataSigners[r.KeyTag]++
			}
		}
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("parsing signed zone: %v", err)
	}
	return keys, dnskeySigners, dataSigners
}

func tagSet(tags ...uint16) map[uint16]bool {
	m := map[uint16]bool{}
	for _, tg := range tags {
		m[tg] = true
	}
	return m
}

// assertPublishedExactly fails unless the DNSKEY RRset holds exactly the given
// tags — the "complete old or intended set, never a third interpretation" check.
func (z *txZone) assertPublishedExactly(t *testing.T, want map[uint16]bool) {
	t.Helper()
	keys, _, _ := z.published(t)
	got := map[uint16]bool{}
	for tg := range keys {
		got[tg] = true
	}
	if len(got) != len(want) {
		t.Fatalf("published DNSKEY tags %v, want exactly %v", got, want)
	}
	for tg := range want {
		if !got[tg] {
			t.Fatalf("published DNSKEY tags %v, want exactly %v", got, want)
		}
	}
}

func liveTag(t *testing.T, kg *KeyGenerator, domain, role string) uint16 {
	t.Helper()
	k, _, err := kg.LoadKeyPair(domain, role)
	if err != nil {
		t.Fatalf("live %s does not load: %v", role, err)
	}
	return k.KeyTag()
}

func failAt(step string) func(string) error {
	return func(s string) error {
		if s == step {
			return errors.New("injected fault at " + step)
		}
		return nil
	}
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- RA6X-002: rollover as a recoverable transaction ------------------------

// Fault-inject every step of a KSK rollover start and "restart" from the
// persisted state. Before the record is saved the old generation must be
// published alone; after it, the intended set (old + new KSK) — never a mix.
func TestKSKRolloverStart_FaultInjectionPublishesOldOrIntendedSet(t *testing.T) {
	steps := []struct {
		name      string
		recorded  bool // the rollover record reaches disk before the fault
		failpoint string
	}{
		{"backup", false, "backup:ksk"},
		{"stage", false, "stage:ksk"},
		{"save", false, ""},
		{"activate", true, "activate:ksk"},
		{"activate-mid", true, "activate-mid:ksk"},
	}
	for _, tc := range steps {
		t.Run(tc.name, func(t *testing.T) {
			z := newTxZone(t)
			rm := NewRolloverManager(z.cfg, z.state)
			if tc.failpoint != "" {
				rm.failpoint = failAt(tc.failpoint)
			} else {
				z.state.SetPath(filepath.Join(t.TempDir(), "missing", "state.json"))
			}
			if err := rm.StartKSKRollover(z.domain); err == nil {
				t.Fatal("StartKSKRollover must report the injected fault")
			}

			st := z.restart(t)
			zs := st.GetZone(z.domain)
			kg := NewKeyGenerator(z.cfg)
			if !tc.recorded {
				if zs.Rollover != nil || zs.KSK.ID != z.oldKSK {
					t.Fatalf("no record may exist before the save; got rollover=%+v ksk=%d", zs.Rollover, zs.KSK.ID)
				}
				if got := liveTag(t, kg, z.domain, "ksk"); got != z.oldKSK {
					t.Fatalf("live KSK must be untouched (tag %d), got %d", z.oldKSK, got)
				}
				if err := NewSigner(z.cfg, st).SignZone(z.domain); err != nil {
					t.Fatalf("signing after restart: %v", err)
				}
				z.assertPublishedExactly(t, tagSet(z.oldKSK, z.oldZSK))
				return
			}
			if zs.Rollover == nil || zs.Rollover.Type != "ksk" || zs.KSK.ID != zs.Rollover.NewKeyID {
				t.Fatalf("the record must be on disk before activation; got %+v", zs.Rollover)
			}
			newKSK := zs.Rollover.NewKeyID
			if err := NewSigner(z.cfg, st).SignZone(z.domain); err != nil {
				t.Fatalf("signing after restart must repair the interrupted activation: %v", err)
			}
			z.assertPublishedExactly(t, tagSet(z.oldKSK, newKSK, z.oldZSK))
			_, dnskeySigners, _ := z.published(t)
			if dnskeySigners[z.oldKSK] == 0 || dnskeySigners[newKSK] == 0 {
				t.Fatalf("DNSKEY RRset must be signed by both KSKs, signers %v", dnskeySigners)
			}
			if got := liveTag(t, kg, z.domain, "ksk"); got != newKSK {
				t.Fatalf("live KSK must be the recorded generation %d, got %d", newKSK, got)
			}
		})
	}
}

// An algorithm rollover is one transaction: failing the ZSK after the KSK was
// staged leaves the old generation live and unrecorded; failing after the
// record is saved is repaired on restart with all four keys published.
func TestAlgorithmRolloverStart_BothPairsAreOneTransaction(t *testing.T) {
	t.Run("zsk staging fails after ksk staged", func(t *testing.T) {
		z := newTxZone(t)
		rm := NewRolloverManager(z.cfg, z.state)
		rm.failpoint = failAt("stage:zsk")
		if err := rm.StartAlgorithmRollover(z.domain, "ECDSAP256SHA256"); err == nil {
			t.Fatal("must fail when the new ZSK cannot be staged")
		}
		zs := z.state.GetZone(z.domain)
		if zs.Rollover != nil || zs.KSK.ID != z.oldKSK || zs.ZSK.ID != z.oldZSK {
			t.Fatalf("in-memory state must be unchanged, got rollover=%+v ksk=%d zsk=%d", zs.Rollover, zs.KSK.ID, zs.ZSK.ID)
		}
		kg := NewKeyGenerator(z.cfg)
		if liveTag(t, kg, z.domain, "ksk") != z.oldKSK || liveTag(t, kg, z.domain, "zsk") != z.oldZSK {
			t.Fatal("live keys must be the old generation")
		}
		st := z.restart(t)
		if err := NewSigner(z.cfg, st).SignZone(z.domain); err != nil {
			t.Fatal(err)
		}
		z.assertPublishedExactly(t, tagSet(z.oldKSK, z.oldZSK))
	})
	t.Run("zsk activation fails after record saved", func(t *testing.T) {
		z := newTxZone(t)
		rm := NewRolloverManager(z.cfg, z.state)
		rm.failpoint = failAt("activate:zsk")
		if err := rm.StartAlgorithmRollover(z.domain, "ECDSAP256SHA256"); err == nil {
			t.Fatal("must report the injected activation fault")
		}
		st := z.restart(t)
		zs := st.GetZone(z.domain)
		if zs.Rollover == nil || zs.Rollover.Type != "algorithm" {
			t.Fatalf("algorithm rollover record must be on disk, got %+v", zs.Rollover)
		}
		newKSK, newZSK := zs.Rollover.NewKeyID, zs.Rollover.NewZSKID
		if err := NewSigner(z.cfg, st).SignZone(z.domain); err != nil {
			t.Fatalf("signing after restart must activate the recorded ZSK: %v", err)
		}
		z.assertPublishedExactly(t, tagSet(z.oldKSK, z.oldZSK, newKSK, newZSK))
		_, dnskeySigners, dataSigners := z.published(t)
		if dnskeySigners[z.oldKSK] == 0 || dnskeySigners[newKSK] == 0 {
			t.Fatalf("DNSKEY RRset must be signed by both algorithms' KSKs, got %v", dnskeySigners)
		}
		if dataSigners[z.oldZSK] == 0 || dataSigners[newZSK] == 0 {
			t.Fatalf("data RRsets must be signed by both algorithms' ZSKs, got %v", dataSigners)
		}
	})
}

// ZSK rollover: persistence failing after staging leaves the live ZSK untouched;
// a crash between the saved record and activation is repaired on restart with
// the pre-publish set (old signs, both published).
func TestZSKRolloverStart_PersistenceAndActivationFaults(t *testing.T) {
	t.Run("save fails", func(t *testing.T) {
		z := newTxZone(t)
		z.state.SetPath(filepath.Join(t.TempDir(), "missing", "state.json"))
		rm := NewRolloverManager(z.cfg, z.state)
		if err := rm.startZSKRollover(z.domain, z.state.GetZone(z.domain)); err == nil {
			t.Fatal("startZSKRollover must fail when the record cannot be saved")
		}
		if z.state.GetZone(z.domain).Rollover != nil {
			t.Fatal("no rollover may remain in memory after a failed save")
		}
		if got := liveTag(t, NewKeyGenerator(z.cfg), z.domain, "zsk"); got != z.oldZSK {
			t.Fatalf("live ZSK must be untouched (tag %d), got %d", z.oldZSK, got)
		}
		st := z.restart(t)
		if err := NewSigner(z.cfg, st).SignZone(z.domain); err != nil {
			t.Fatal(err)
		}
		z.assertPublishedExactly(t, tagSet(z.oldKSK, z.oldZSK))
	})
	t.Run("crash before activation", func(t *testing.T) {
		z := newTxZone(t)
		rm := NewRolloverManager(z.cfg, z.state)
		rm.failpoint = failAt("activate:zsk")
		if err := rm.startZSKRollover(z.domain, z.state.GetZone(z.domain)); err == nil {
			t.Fatal("must report the injected activation fault")
		}
		st := z.restart(t)
		zs := st.GetZone(z.domain)
		if zs.Rollover == nil || zs.Rollover.State != statepkg.ZSKRolloverStatePrePublish || zs.ZSK.ID != z.oldZSK {
			t.Fatalf("pre-publish record with the old ZSK still signing must be on disk, got %+v zsk=%d", zs.Rollover, zs.ZSK.ID)
		}
		newZSK := zs.Rollover.NewKeyID
		if err := NewSigner(z.cfg, st).SignZone(z.domain); err != nil {
			t.Fatalf("signing after restart must activate the pre-published ZSK: %v", err)
		}
		z.assertPublishedExactly(t, tagSet(z.oldKSK, z.oldZSK, newZSK))
		_, _, dataSigners := z.published(t)
		for tg := range dataSigners {
			if tg != z.oldZSK {
				t.Fatalf("pre-publish must keep signing with the old ZSK %d, got signer %d", z.oldZSK, tg)
			}
		}
		if got := liveTag(t, NewKeyGenerator(z.cfg), z.domain, "zsk"); got != newZSK {
			t.Fatalf("live ZSK slot must hold the pre-published key %d, got %d", newZSK, got)
		}
	})
}

// A live pair the recorded state does not name — and for which no verified copy
// of the recorded generation exists — must not be signed with. The previous
// signed zone stays in place.
func TestSignZone_RefusesLiveKeyNotNamedByState(t *testing.T) {
	z := newTxZone(t)
	before := readFile(t, z.signedPath())
	zs := z.state.GetZone(z.domain)
	z.state.Mutate(func() { zs.KSK.ID = z.oldKSK + 1 })
	err := NewSigner(z.cfg, z.state).SignZone(z.domain)
	if err == nil || !strings.Contains(err.Error(), "refusing to sign") {
		t.Fatalf("signing with an unrecorded live key must fail closed, got %v", err)
	}
	if !bytes.Equal(before, readFile(t, z.signedPath())) {
		t.Fatal("the previous signed zone must be left in place")
	}
}

// A mixed live pair (new .private beside old .key — the mid-activation crash
// artifact) is repaired from the recorded generation's tag-named copy.
func TestSignZone_RepairsMixedLivePairFromRecordedGeneration(t *testing.T) {
	z := newTxZone(t)
	kg := NewKeyGenerator(z.cfg)
	oldKey := readFile(t, kg.liveBase(z.domain, "ksk")+".key")
	rm := NewRolloverManager(z.cfg, z.state)
	if err := rm.StartKSKRollover(z.domain); err != nil {
		t.Fatal(err)
	}
	newKSK := z.state.GetZone(z.domain).Rollover.NewKeyID
	if err := os.WriteFile(kg.liveBase(z.domain, "ksk")+".key", oldKey, 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := kg.LoadKeyPair(z.domain, "ksk"); err == nil {
		t.Fatal("fixture: the mixed pair must not load")
	}
	if err := NewSigner(z.cfg, z.state).SignZone(z.domain); err != nil {
		t.Fatalf("signing must repair the mixed live pair: %v", err)
	}
	z.assertPublishedExactly(t, tagSet(z.oldKSK, newKSK, z.oldZSK))
	if got := liveTag(t, kg, z.domain, "ksk"); got != newKSK {
		t.Fatalf("live KSK must be %d after repair, got %d", newKSK, got)
	}
}

// A tag-named file holding a key with a different tag must not stand in for
// the recorded key.
func TestLoadByID_RejectsTagMismatch(t *testing.T) {
	z := newTxZone(t)
	kg := NewKeyGenerator(z.cfg)
	wrong := kg.taggedBase(z.domain, "ksk", z.oldKSK+7)
	for _, ext := range []string{".key", ".private"} {
		if err := os.WriteFile(wrong+ext, readFile(t, kg.liveBase(z.domain, "ksk")+ext), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := kg.LoadKeyPairByID(z.domain, "ksk", z.oldKSK+7); err == nil {
		t.Fatal("LoadKeyPairByID must reject a file whose key tag differs from its name")
	}
	if _, err := kg.LoadPublicKeyByID(z.domain, "ksk", z.oldKSK+7); err == nil {
		t.Fatal("LoadPublicKeyByID must reject a file whose key tag differs from its name")
	}
	// The rollover start refuses a live key the state does not name.
	zs := z.state.GetZone(z.domain)
	z.state.Mutate(func() { zs.KSK.ID = z.oldKSK + 7 })
	if err := NewRolloverManager(z.cfg, z.state).StartKSKRollover(z.domain); err == nil {
		t.Fatal("StartKSKRollover must refuse when the live KSK is not the recorded key")
	}
}

// --- RA6X-023: verified backups before any live overwrite ------------------

func otherPrivateFile(t *testing.T, cfg *config.Config, domain string) []byte {
	t.Helper()
	kg := NewKeyGenerator(cfg)
	dnskey, priv, _, err := kg.generateKeyMaterial(domain, true, "")
	if err != nil {
		t.Fatal(err)
	}
	return []byte(formatPrivateKey(dnskey, priv))
}

// Every damaged form of a private backup half must be repaired from the
// verified live pair — with the damaged file kept for diagnosis — before the
// rollover replaces the live key, and the rollover must then sign with both.
func TestBackupKey_RepairsDamagedPrivateBackup(t *testing.T) {
	cases := []struct {
		name    string
		damage  func(t *testing.T, z *txZone, backupPriv string, livePriv []byte) []byte // returns the damaged bytes (nil = absent)
		present bool
	}{
		{"missing", func(t *testing.T, z *txZone, p string, live []byte) []byte { return nil }, false},
		{"zero-length", func(t *testing.T, z *txZone, p string, live []byte) []byte { return []byte{} }, true},
		{"truncated", func(t *testing.T, z *txZone, p string, live []byte) []byte { return live[:len(live)/2] }, true},
		{"mismatched", func(t *testing.T, z *txZone, p string, live []byte) []byte {
			return otherPrivateFile(t, z.cfg, z.domain)
		}, true},
		{"garbage", func(t *testing.T, z *txZone, p string, live []byte) []byte {
			return []byte("PrivateKey: not-base64!!\n")
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z := newTxZone(t)
			kg := NewKeyGenerator(z.cfg)
			live := kg.liveBase(z.domain, "ksk")
			backup := kg.taggedBase(z.domain, "ksk", z.oldKSK)
			liveKey, livePriv := readFile(t, live+".key"), readFile(t, live+".private")
			// The tag-named copy exists from generation; damage its private half.
			damaged := tc.damage(t, z, backup+".private", livePriv)
			if tc.present {
				if err := os.WriteFile(backup+".private", damaged, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Remove(backup + ".private"); err != nil {
				t.Fatal(err)
			}

			rm := NewRolloverManager(z.cfg, z.state)
			if err := rm.BackupKey(z.domain, "ksk", z.oldKSK); err != nil {
				t.Fatalf("BackupKey must repair a %s private backup: %v", tc.name, err)
			}
			if !bytes.Equal(readFile(t, backup+".private"), livePriv) {
				t.Fatal("repaired backup must hold the live private key material")
			}
			if _, _, err := kg.LoadKeyPairByID(z.domain, "ksk", z.oldKSK); err != nil {
				t.Fatalf("repaired backup must verify: %v", err)
			}
			if tc.present {
				aside := backup + ".private.invalid.0"
				if !bytes.Equal(readFile(t, aside), damaged) {
					t.Fatalf("damaged material must be preserved at %s", aside)
				}
			}
			if !bytes.Equal(readFile(t, live+".key"), liveKey) || !bytes.Equal(readFile(t, live+".private"), livePriv) {
				t.Fatal("live pair must be untouched by the repair")
			}

			// The rollover now proceeds and signs with both generations.
			if err := rm.StartKSKRollover(z.domain); err != nil {
				t.Fatalf("StartKSKRollover after repair: %v", err)
			}
			if err := NewSigner(z.cfg, z.state).SignZone(z.domain); err != nil {
				t.Fatalf("signing with the repaired old KSK: %v", err)
			}
			z.assertPublishedExactly(t, tagSet(z.oldKSK, z.state.GetZone(z.domain).Rollover.NewKeyID, z.oldZSK))
		})
	}
}

// The review's probe: a valid backup whose private half was truncated to
// nothing used to let the rollover start and then fail at signing with the
// only usable copy of the old private key already overwritten.
func TestKSKRolloverStart_TruncatedBackupNeverDestroysOldKey(t *testing.T) {
	z := newTxZone(t)
	kg := NewKeyGenerator(z.cfg)
	rm := NewRolloverManager(z.cfg, z.state)
	if err := rm.BackupKey(z.domain, "ksk", z.oldKSK); err != nil {
		t.Fatal(err)
	}
	backup := kg.taggedBase(z.domain, "ksk", z.oldKSK)
	if err := os.Truncate(backup+".private", 0); err != nil {
		t.Fatal(err)
	}
	if err := rm.StartKSKRollover(z.domain); err != nil {
		t.Fatalf("rollover start must repair the backup and proceed: %v", err)
	}
	if err := NewSigner(z.cfg, z.state).SignZone(z.domain); err != nil {
		t.Fatalf("signing after rollover start must load the old KSK from its backup: %v", err)
	}
	newKSK := z.state.GetZone(z.domain).Rollover.NewKeyID
	z.assertPublishedExactly(t, tagSet(z.oldKSK, newKSK, z.oldZSK))
}

// An unreadable private backup cannot be trusted: the rollover aborts before
// any live replacement and records nothing.
func TestKSKRolloverStart_UnreadableBackupFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("relies on filesystem permissions; not meaningful as root")
	}
	z := newTxZone(t)
	kg := NewKeyGenerator(z.cfg)
	backup := kg.taggedBase(z.domain, "ksk", z.oldKSK)
	if err := os.Chmod(backup+".private", 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(backup+".private", 0600)
	live := kg.liveBase(z.domain, "ksk")
	liveKey, livePriv := readFile(t, live+".key"), readFile(t, live+".private")

	rm := NewRolloverManager(z.cfg, z.state)
	if err := rm.StartKSKRollover(z.domain); err == nil {
		t.Fatal("rollover must refuse to proceed over an unreadable backup")
	}
	if z.state.GetZone(z.domain).Rollover != nil {
		t.Fatal("no rollover may be recorded")
	}
	if !bytes.Equal(readFile(t, live+".key"), liveKey) || !bytes.Equal(readFile(t, live+".private"), livePriv) {
		t.Fatal("live pair must be untouched")
	}
}

// Implicit backup during key generation (the SaveKeyFiles path used by add and
// import): a same-key backup with an empty private half is repaired before the
// live pair is overwritten, and the old key stays loadable by ID.
func TestSaveKeyFiles_ImplicitBackupRepairsDamagedHalf(t *testing.T) {
	z := newTxZone(t)
	kg := NewKeyGenerator(z.cfg)
	live := kg.liveBase(z.domain, "ksk")
	backup := kg.taggedBase(z.domain, "ksk", z.oldKSK)
	oldPriv := readFile(t, live+".private")
	if err := os.WriteFile(backup+".private", nil, 0600); err != nil {
		t.Fatal(err)
	}
	newKSK, err := kg.GenerateKSK(z.domain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readFile(t, backup+".private"), oldPriv) {
		t.Fatal("the old private key must be restored into its backup before the overwrite")
	}
	if _, _, err := kg.LoadKeyPairByID(z.domain, "ksk", z.oldKSK); err != nil {
		t.Fatalf("old key must remain loadable by ID: %v", err)
	}
	if got := liveTag(t, kg, z.domain, "ksk"); got != newKSK.ID {
		t.Fatalf("live KSK must be the new key %d, got %d", newKSK.ID, got)
	}
	if !FileExists(backup + ".private.invalid.0") {
		t.Fatal("the damaged half must be kept for diagnosis")
	}
}

// A tag slot occupied by a DIFFERENT key is never overwritten: the live key is
// preserved under a unique name instead, and the foreign key is untouched.
func TestSaveKeyFiles_TagCollisionNeverOverwritesDifferentKey(t *testing.T) {
	z := newTxZone(t)
	kg := NewKeyGenerator(z.cfg)
	backup := kg.taggedBase(z.domain, "ksk", z.oldKSK)
	foreignKey, foreignPriv, _, err := kg.generateKeyMaterial(z.domain, true, "")
	if err != nil {
		t.Fatal(err)
	}
	foreignKeyFile := []byte("; foreign\n" + foreignKey.String() + "\n")
	foreignPrivFile := []byte(formatPrivateKey(foreignKey, foreignPriv))
	if err := os.WriteFile(backup+".key", foreignKeyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup+".private", foreignPrivFile, 0600); err != nil {
		t.Fatal(err)
	}
	live := kg.liveBase(z.domain, "ksk")
	oldKey, oldPriv := readFile(t, live+".key"), readFile(t, live+".private")

	if _, err := kg.GenerateKSK(z.domain); err != nil {
		t.Fatalf("generation over a colliding backup must preserve and proceed: %v", err)
	}
	if !bytes.Equal(readFile(t, backup+".key"), foreignKeyFile) || !bytes.Equal(readFile(t, backup+".private"), foreignPrivFile) {
		t.Fatal("the different key at the tag slot must be untouched")
	}
	if !bytes.Equal(readFile(t, backup+".0.key"), oldKey) || !bytes.Equal(readFile(t, backup+".0.private"), oldPriv) {
		t.Fatal("the displaced live key must be preserved under a unique name")
	}
	if _, _, err := kg.loadVerifiedPair(backup+".0", z.domain, "ksk"); err != nil {
		t.Fatalf("preserved pair must verify: %v", err)
	}
	// The direct rollover backup refuses the same collision.
	if err := NewRolloverManager(z.cfg, z.state).BackupKey(z.domain, "ksk", z.oldKSK); err == nil {
		t.Fatal("BackupKey must refuse a tag slot holding a different key")
	}
}

// --- RA6X-030: private-key correspondence ----------------------------------

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 0x01
	return c
}

func TestVerifyKeyPairCorrespondence_Ed25519Forms(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dnskey := ed25519DNSKEY(pub)
	seed := priv.Seed()
	cases := []struct {
		name string
		priv []byte
		key  *dns.DNSKEY
		ok   bool
	}{
		{"valid seed", seed, dnskey, true},
		{"valid expanded", priv, dnskey, true},
		{"seed corrupted, suffix intact", flip(priv, 0), dnskey, false},
		{"suffix corrupted, seed intact", flip(priv, ed25519.SeedSize), dnskey, false},
		{"32-byte seed corrupted", flip(seed, 5), dnskey, false},
		{"public half corrupted", priv, ed25519DNSKEY(flip(pub, 3)), false},
		{"truncated seed (31)", seed[:31], dnskey, false},
		{"oversized seed (33)", append(append([]byte(nil), seed...), 0), dnskey, false},
		{"truncated expanded (63)", priv[:63], dnskey, false},
		{"oversized expanded (65)", append(append([]byte(nil), priv...), 0), dnskey, false},
		{"empty", nil, dnskey, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyKeyPairCorrespondence(tc.key, tc.priv)
			if tc.ok && err != nil {
				t.Fatalf("valid form rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("malformed form accepted")
			}
			if !tc.ok {
				return
			}
			// Valid forms must sign and verify.
			s := &Signer{}
			rrset := sampleRRset()
			rrsig := s.createRRSIG(rrset, tc.key, "example.com.", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
			if err := s.signRRSIG(rrsig, rrset, tc.key, tc.priv); err != nil {
				t.Fatal(err)
			}
			if err := rrsig.Verify(tc.key, rrset); err != nil {
				t.Fatalf("signature from a valid form must verify: %v", err)
			}
		})
	}
}

// The probe from the review: a corrupted seed under an intact suffix used to
// pass and then sign under a key nobody published. Signing now derives from
// the seed and the pair is rejected up front.
func TestVerifyKeyPairCorrespondence_CorruptSeedNoLongerSignsUnderWrongKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dnskey := ed25519DNSKEY(pub)
	corrupt := flip(priv, 0)
	if err := VerifyKeyPairCorrespondence(dnskey, corrupt); err == nil {
		t.Fatal("corrupted seed with intact suffix must be rejected")
	}
	s := &Signer{}
	rrset := sampleRRset()
	rrsig := s.createRRSIG(rrset, dnskey, "example.com.", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err := s.signRRSIG(rrsig, rrset, dnskey, corrupt); err != nil {
		t.Fatal(err)
	}
	if err := rrsig.Verify(dnskey, rrset); err == nil {
		t.Fatal("a signature from the corrupted seed must not verify under the advertised key (it was made under the seed's real key)")
	}
}

func TestVerifyKeyPairCorrespondence_ECDSAScalarRange(t *testing.T) {
	curves := []struct {
		name string
		alg  uint8
		c    elliptic.Curve
		size int
	}{
		{"P-256", dns.ECDSAP256SHA256, elliptic.P256(), 32},
		{"P-384", dns.ECDSAP384SHA384, elliptic.P384(), 48},
	}
	for _, cv := range curves {
		t.Run(cv.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(cv.c, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			pubBytes := make([]byte, 2*cv.size)
			key.X.FillBytes(pubBytes[:cv.size])
			key.Y.FillBytes(pubBytes[cv.size:])
			dnskey := &dns.DNSKEY{
				Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
				Flags: 256, Protocol: 3, Algorithm: cv.alg,
				PublicKey: base64.StdEncoding.EncodeToString(pubBytes),
			}
			valid := make([]byte, cv.size)
			key.D.FillBytes(valid)
			n := cv.c.Params().N
			fixed := func(v *big.Int) []byte { b := make([]byte, cv.size); v.FillBytes(b); return b }

			if err := VerifyKeyPairCorrespondence(dnskey, valid); err != nil {
				t.Fatalf("valid scalar rejected: %v", err)
			}
			bad := map[string][]byte{
				"zero":           make([]byte, cv.size),
				"order n":        fixed(n),
				"order n+1":      fixed(new(big.Int).Add(n, big.NewInt(1))),
				"all 0xff":       bytes.Repeat([]byte{0xff}, cv.size),
				"flipped":        flip(valid, 0),
				"truncated":      valid[:cv.size-1],
				"oversized":      append(append([]byte(nil), valid...), 0),
				"public flipped": valid,
			}
			for name, priv := range bad {
				k := dnskey
				if name == "public flipped" {
					k = &dns.DNSKEY{Hdr: dnskey.Hdr, Flags: 256, Protocol: 3, Algorithm: cv.alg,
						PublicKey: base64.StdEncoding.EncodeToString(flip(pubBytes, 1))}
				}
				if err := VerifyKeyPairCorrespondence(k, priv); err == nil {
					t.Errorf("%s: malformed ECDSA key accepted", name)
				}
			}
		})
	}
}

// Malformed key material never reaches disk: staging rejects it before any write.
func TestStageKeyPair_RejectsMalformedMaterial(t *testing.T) {
	z := newTxZone(t)
	kg := NewKeyGenerator(z.cfg)
	dnskey, priv, _, err := kg.generateKeyMaterial(z.domain, true, "")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadDir(z.cfg.KeysDir())
	if _, err := kg.StageKeyPair(z.domain, "ksk", dnskey, flip(priv, 0)); err == nil {
		t.Fatal("staging a non-corresponding pair must fail")
	}
	after, _ := os.ReadDir(z.cfg.KeysDir())
	if len(before) != len(after) {
		t.Fatalf("no file may be written for rejected material (%d → %d entries)", len(before), len(after))
	}
	if err := kg.SaveKeyFiles(z.domain, "ksk", dnskey, flip(priv, 0)); err == nil {
		t.Fatal("SaveKeyFiles must reject a non-corresponding pair")
	}
	if got := liveTag(t, kg, z.domain, "ksk"); got != z.oldKSK {
		t.Fatalf("live KSK must be untouched, got %d", got)
	}
}
