package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"

	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/ptudor/dnssec-tudor/internal/config"
)

// --- Item 1: unwindAdd must never delete a surviving orphan key half ---

// keyPairAbsent must report true only when NEITHER half of the pair exists.
// A half-present pair means RecoverOrGenerateKeys refuses (R-028) rather than
// generates, so a failed add's rollback must not treat it as "generated here".
func TestKeyPairAbsent(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		want  bool
	}{
		{"neither_half", nil, true},
		{"private_only_orphan", []string{"example.com.ksk.private"}, false},
		{"key_only_orphan", []string{"example.com.ksk.key"}, false},
		{"both_halves", []string{"example.com.ksk.key", "example.com.ksk.private"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keysDir := t.TempDir()
			for _, f := range tc.files {
				if err := os.WriteFile(filepath.Join(keysDir, f), []byte("key material"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got := keyPairAbsent(keysDir, "example.com", "ksk"); got != tc.want {
				t.Errorf("keyPairAbsent(%v) = %v, want %v", tc.files, got, tc.want)
			}
		})
	}
}

// With the flags computed by keyPairAbsent, the failed-add unwind must leave a
// .private-only orphan on disk — it is the only recoverable copy of a key
// whose DS may still be live at the parent.
func TestUnwindAdd_PreservesPrivateOnlyOrphan(t *testing.T) {
	dir := t.TempDir()
	cfg := dnssectest.Config(t, dir)
	keysDir := cfg.KeysDir()
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(keysDir, "example.com.ksk.private")
	if err := os.WriteFile(orphan, []byte("orphaned private key material"), 0600); err != nil {
		t.Fatal(err)
	}

	state := statepkg.NewState(cfg.StatePath())
	state.SetZone("example.com", &statepkg.ZoneState{Path: "/zones/example.com.db"})

	// Exactly what runAdd computes before RecoverOrGenerateKeys fails on the
	// incomplete pair: the KSK slot is NOT empty (orphan half present), the
	// ZSK slot is.
	kskGenerated := keyPairAbsent(keysDir, "example.com", "ksk")
	zskGenerated := keyPairAbsent(keysDir, "example.com", "zsk")
	if kskGenerated {
		t.Fatal("kskGenerated must be false with a .private orphan present")
	}
	if !zskGenerated {
		t.Fatal("zskGenerated must be true with no ZSK files present")
	}

	unwindAdd(cfg, state, "example.com", kskGenerated, zskGenerated, nil, false)

	if !signerpkg.FileExists(orphan) {
		t.Fatal("unwindAdd deleted the surviving .private orphan — the only recoverable copy of the key")
	}
	if state.GetZone("example.com") != nil {
		t.Error("unwindAdd should have removed the zone from in-memory state")
	}
}

// End-to-end failed-add: a .private-only KSK orphan makes RecoverOrGenerateKeys
// refuse, and the rollback must leave the orphan on disk while cleaning up the
// zone from state and leaving the config file untouched.
func TestRunAdd_FailedAddPreservesPrivateOnlyOrphan(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	content := fmt.Sprintf("output_dir = %q\ndata_dir = %q\n", filepath.Join(dir, "signed"), dir)
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	zonePath := filepath.Join(dir, "example.com.db")
	zone := "example.com. 3600 IN SOA ns.example.com. admin.example.com. 1 3600 600 86400 3600\n" +
		"example.com. 3600 IN NS ns.example.com.\n"
	if err := os.WriteFile(zonePath, []byte(zone), 0644); err != nil {
		t.Fatal(err)
	}

	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(keysDir, "example.com.ksk.private")
	if err := os.WriteFile(orphan, []byte("orphaned private key material"), 0600); err != nil {
		t.Fatal(err)
	}

	origConfigPath := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = origConfigPath })

	err := runAdd(nil, []string{"example.com", zonePath})
	if err == nil {
		t.Fatal("runAdd should fail on a .private-only KSK orphan")
	}
	if !strings.Contains(err.Error(), "preparing keys") {
		t.Errorf("error should come from key preparation, got: %v", err)
	}

	if !signerpkg.FileExists(orphan) {
		t.Fatal("failed add deleted the surviving .private orphan — the only recoverable copy of the key")
	}

	// Rollback left no half-added zone behind: state has no entry and the
	// config file was not appended.
	reloaded, lerr := statepkg.LoadState(filepath.Join(dir, "state.json"))
	if lerr != nil {
		t.Fatalf("LoadState: %v", lerr)
	}
	if reloaded.GetZone("example.com") != nil {
		t.Error("failed add left the zone in state.json")
	}
	cfgOut, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if strings.Contains(string(cfgOut), "[zones.") {
		t.Errorf("failed add left a zone entry in the config file:\n%s", cfgOut)
	}
}

// --- Item 9: syslog connection must be closed on SIGHUP re-setup ---

type fakeCloser struct {
	closed int
}

func (f *fakeCloser) Close() error {
	f.closed++
	return nil
}

// closeSyslogWriter must close exactly the tracked writer once, clear the
// tracker, and be nil-safe (fresh startup / Windows / non-syslog outputs).
func TestCloseSyslogWriter_ClosesAndClearsTracker(t *testing.T) {
	origCloser := syslogCloser
	t.Cleanup(func() { syslogCloser = origCloser })

	// Nil-safe: nothing tracked must not panic.
	syslogCloser = nil
	closeSyslogWriter()

	fc := &fakeCloser{}
	syslogCloser = fc
	closeSyslogWriter()
	if fc.closed != 1 {
		t.Fatalf("previous syslog writer closed %d times, want 1", fc.closed)
	}
	if syslogCloser != nil {
		t.Fatal("tracker must be cleared after close")
	}

	// Idempotent: a second run has nothing left to close.
	closeSyslogWriter()
	if fc.closed != 1 {
		t.Fatalf("writer closed again on an empty tracker: %d closes", fc.closed)
	}
}

// Re-running setupLogging with a file --log-output (the SIGHUP reopen) must
// behave as before and must not disturb the syslog tracker — the branches are
// independent, and the file path never dials or closes syslog.
func TestSetupLogging_FileOutputLeavesSyslogTrackerAlone(t *testing.T) {
	origLevel, origFormat, origOutput, origFile := logLevel, logFormat, logOutput, logFile
	origCloser := syslogCloser
	origDefault := slog.Default()
	t.Cleanup(func() {
		if logFile != nil && logFile != origFile {
			logFile.Close()
		}
		logLevel, logFormat, logOutput, logFile = origLevel, origFormat, origOutput, origFile
		syslogCloser = origCloser
		slog.SetDefault(origDefault)
	})

	fc := &fakeCloser{}
	syslogCloser = fc

	dir := t.TempDir()
	logPath := filepath.Join(dir, "daemon.log")
	logLevel, logFormat, logOutput = "info", "text", logPath

	setupLogging()
	slog.Info("first line")
	setupLogging() // SIGHUP re-run
	slog.Info("second line")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("log file not created: %v", err)
	}
	if !strings.Contains(string(data), "second line") {
		t.Errorf("second line not written after re-run: %q", data)
	}
	if fc.closed != 0 {
		t.Errorf("file-output setupLogging closed the syslog writer %d times, want 0", fc.closed)
	}
	if syslogCloser != fc {
		t.Error("file-output setupLogging must not replace the syslog tracker")
	}
}

// --- Item 11: `remove` must not silently succeed on unrewritable headers ---

// The matcher recognizes the TOML-equivalent header variants and rejects
// near-misses (different domain, trailing junk, non-header lines).
func TestIsZoneTableHeader(t *testing.T) {
	const domain = "b.example.com"
	cases := []struct {
		line string
		want bool
	}{
		{`[zones."b.example.com"]`, true},
		{`[zones.'b.example.com']`, true},
		{`   [zones."b.example.com"]   `, true},
		{`[zones."b.example.com"] # trailing comment`, true},
		{`  [zones.'b.example.com']  # comment  `, true},
		{`[zones."other.example.com"]`, false},
		{`[zones."b.example.com.evil"]`, false},
		{`[zones."b.example.com"] path = "/x"`, false}, // trailing junk that isn't a comment
		{`path = "/zones/b.db"`, false},
		{`[zonesx."b.example.com"]`, false},
		{`[zones.b.example.com]`, false}, // unquoted form parses as nested tables, never a zone
		{``, false},
	}
	for _, tc := range cases {
		if got := config.IsZoneTableHeader(tc.line, domain); got != tc.want {
			t.Errorf("isZoneTableHeader(%q) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// When the parsed config confirms the zone is present but the rewriter cannot
// locate its table header (here: TOML-valid whitespace inside the brackets,
// which the anchored matcher deliberately does not chase), runRemove must
// return an error — never print success while the entry survives in the file.
func TestRunRemove_ErrorsWhenHeaderNotRewritable(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	zonePath := filepath.Join(dir, "gone.example.com.db")
	content := fmt.Sprintf(`output_dir = %q
data_dir = %q

[ zones . "gone.example.com" ]
path = %q
`, filepath.Join(dir, "signed"), dir, zonePath)
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	state := statepkg.NewState(filepath.Join(dir, "state.json"))
	state.SetZone("gone.example.com", &statepkg.ZoneState{Path: zonePath})
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	origConfigPath := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = origConfigPath })

	// Sanity: the exotic header parses as the zone, so runRemove takes the
	// in-config branch — the exact combination that used to print success.
	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if _, ok := cfg.Zones["gone.example.com"]; !ok {
		t.Fatal("fixture header did not parse as the zone; test premise broken")
	}

	err = runRemove(nil, []string{"gone.example.com"})
	if err == nil {
		t.Fatal("runRemove should fail when the config entry cannot be rewritten")
	}
	if !strings.Contains(err.Error(), "could not be located") {
		t.Errorf("error should tell the operator to remove the entry by hand, got: %v", err)
	}

	// Nothing was mutated: the config still holds the entry and the zone is
	// still managed in state.json.
	out, rerr := os.ReadFile(cfgPath)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(out), `[ zones . "gone.example.com" ]`) {
		t.Errorf("config entry must be left intact on failure:\n%s", out)
	}
	reloaded, lerr := statepkg.LoadState(filepath.Join(dir, "state.json"))
	if lerr != nil {
		t.Fatalf("LoadState: %v", lerr)
	}
	if reloaded.GetZone("gone.example.com") == nil {
		t.Error("state must be left intact when the config rewrite fails")
	}
}
