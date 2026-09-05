package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ptudor/dnssec-tudor/internal/config"
	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
	"github.com/spf13/cobra"
)

// --- RA6X-034: hook lifetime bounds ------------------------------------------

func shortHookTimeouts(t *testing.T) {
	t.Helper()
	origT, origW, origK := hookTimeout, hookWaitDelay, hookKillGrace
	hookTimeout, hookWaitDelay, hookKillGrace = 1*time.Second, 1*time.Second, 300*time.Millisecond
	t.Cleanup(func() { hookTimeout, hookWaitDelay, hookKillGrace = origT, origW, origK })
}

func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil
}

// A shell hook whose child inherits stderr and outlives the shell must not
// hold the caller past the timeout, and the child must be terminated.
func TestHookTimeout_BoundsDescendantsHoldingStderr(t *testing.T) {
	shortHookTimeouts(t)
	cases := map[string]func(pidFile string) *config.HooksConfig{
		"shell-style": func(pidFile string) *config.HooksConfig {
			return &config.HooksConfig{Shell: true, PostSign: fmt.Sprintf("sleep 30 & echo $! > %s; wait", pidFile)}
		},
		"exec-style": func(pidFile string) *config.HooksConfig {
			return &config.HooksConfig{PostSignCmd: []string{"/bin/sh", "-c", fmt.Sprintf("sleep 30 & echo $! > %s; wait", pidFile)}}
		},
		"child ignores SIGTERM": func(pidFile string) *config.HooksConfig {
			return &config.HooksConfig{PostSignCmd: []string{"/bin/sh", "-c", fmt.Sprintf("trap '' TERM; sleep 30 & echo $! > %s; wait", pidFile)}}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			// Let a previous subtest's kill goroutine finish before the
			// timing variables are restored.
			t.Cleanup(func() { time.Sleep(hookKillGrace + 100*time.Millisecond) })
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			hooks := mk(pidFile)
			start := time.Now()
			err := firePostSignHooks(hooks, "/tmp", []SignedZoneRef{{Domain: "x.example"}}, nil)
			elapsed := time.Since(start)
			if err == nil || !strings.Contains(err.Error(), "timed out") {
				t.Fatalf("hook must report a timeout, got %v", err)
			}
			if elapsed > hookTimeout+hookWaitDelay+2*time.Second {
				t.Fatalf("hook held the caller for %s, want < %s", elapsed, hookTimeout+hookWaitDelay+2*time.Second)
			}
			data, rerr := os.ReadFile(pidFile)
			if rerr != nil {
				t.Fatalf("child pid not recorded: %v", rerr)
			}
			pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
			deadline := time.Now().Add(3 * time.Second)
			for pidAlive(pid) && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			if pidAlive(pid) {
				syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("descendant %d survived the hook timeout", pid)
			}
		})
	}
}

// A hook that finishes within budget still succeeds, and a failing hook still
// reports its stderr prefix.
func TestHook_WithinBudgetAndStderrPrefix(t *testing.T) {
	shortHookTimeouts(t)
	hooks := &config.HooksConfig{PostSignCmd: []string{"/bin/sh", "-c", "sleep 0.2; exit 0"}}
	if err := firePostSignHooks(hooks, "/tmp", []SignedZoneRef{{Domain: "x.example"}}, nil); err != nil {
		t.Fatalf("a hook within budget must succeed: %v", err)
	}
	stderr, err := runHook(&config.HooksConfig{PostSignCmd: []string{"/bin/sh", "-c", "echo boom >&2; exit 3"}}, hookEnviron(), os.Stdout)
	if err == nil || stderr != "boom" {
		t.Fatalf("failing hook must return its stderr prefix, got stderr=%q err=%v", stderr, err)
	}
}

// --- RA6X-043: CLI hook contract ---------------------------------------------

// hookRecorder is a hook that appends every DNSSEC_* variable of each
// invocation to a log file, one invocation per block.
type hookRecorder struct {
	log string
}

func newHookRecorder(t *testing.T) *hookRecorder {
	t.Helper()
	return &hookRecorder{log: filepath.Join(t.TempDir(), "hook.log")}
}

func (h *hookRecorder) cmd() []string {
	return []string{"/bin/sh", "-c", "{ env | grep '^DNSSEC_' | sort; echo '--'; } >> " + h.log}
}

// invocations parses the recorded blocks into maps.
func (h *hookRecorder) invocations(t *testing.T) []map[string]string {
	t.Helper()
	data, err := os.ReadFile(h.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]string
	for _, block := range strings.Split(strings.TrimSpace(string(data)), "--") {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		m := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			k, v, _ := strings.Cut(line, "=")
			m[k] = v
		}
		out = append(out, m)
	}
	return out
}

func (h *hookRecorder) reset() { os.Remove(h.log) }

// cliZones is a config file with hooks and N zones, plus keys in state, so the
// real CLI handlers can run against it.
type cliZones struct {
	dir      string
	cfgPath  string
	cfg      *config.Config
	state    *statepkg.State
	zones    map[string]string // domain → zone path
	recorder *hookRecorder
}

func newCLIZones(t *testing.T, coalesce bool, domains ...string) *cliZones {
	t.Helper()
	dir := t.TempDir()
	rec := newHookRecorder(t)
	local := dnssectest.Config(t, dir)
	for _, d := range []string{local.KeysDir(), local.OutputDir} {
		if err := signerpkg.EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	z := &cliZones{dir: dir, cfgPath: filepath.Join(dir, "config.toml"), cfg: local, zones: map[string]string{}, recorder: rec}
	var sb strings.Builder
	fmt.Fprintf(&sb, "output_dir = %q\ndata_dir = %q\n\n[hooks]\npost_sign_cmd = [%q, %q, %q]\ncoalesce_post_sign = %v\n",
		local.OutputDir, dir, rec.cmd()[0], rec.cmd()[1], rec.cmd()[2], coalesce)
	st := statepkg.NewState(local.StatePath())
	kg := signerpkg.NewKeyGenerator(local)
	for _, domain := range domains {
		zp := filepath.Join(dir, domain+".zone")
		if err := os.WriteFile(zp, []byte(validZoneContent(domain)), 0644); err != nil {
			t.Fatal(err)
		}
		z.zones[domain] = zp
		fmt.Fprintf(&sb, "\n[zones.%q]\npath = %q\n", domain, zp)
		local.Zones[domain] = config.ZoneConfig{Path: zp}
		ksk, err := kg.GenerateKSK(domain)
		if err != nil {
			t.Fatal(err)
		}
		zsk, err := kg.GenerateZSK(domain)
		if err != nil {
			t.Fatal(err)
		}
		st.SetZone(domain, &statepkg.ZoneState{Path: zp, KSK: ksk, ZSK: zsk})
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(z.cfgPath, []byte(sb.String()), 0600); err != nil {
		t.Fatal(err)
	}
	z.state = st
	orig := configPath
	configPath = z.cfgPath
	t.Cleanup(func() { configPath = orig })
	// Stale opposite-mode variables in the parent environment must never
	// reach a hook.
	t.Setenv("DNSSEC_DOMAIN", "stale.example")
	t.Setenv("DNSSEC_DOMAINS", "stale.example other.example")
	t.Setenv("DNSSEC_BATCH_SIZE", "99")
	return z
}

func (z *cliZones) signedPath(domain string) string {
	return filepath.Join(z.cfg.OutputDir, domain+".zone.signed")
}

// assertPerZone checks one per-zone invocation per expected domain with exact
// paths and no batch variables.
func (z *cliZones) assertPerZone(t *testing.T, inv []map[string]string, want ...string) {
	t.Helper()
	if len(inv) != len(want) {
		t.Fatalf("expected %d per-zone invocations, got %d: %v", len(want), len(inv), inv)
	}
	var got []string
	for _, m := range inv {
		d := m["DNSSEC_DOMAIN"]
		got = append(got, d)
		if m["DNSSEC_ZONE_PATH"] != z.zones[d] || m["DNSSEC_SIGNED_PATH"] != z.signedPath(d) || m["DNSSEC_OUTPUT_DIR"] != z.cfg.OutputDir {
			t.Fatalf("per-zone variables for %s wrong: %v", d, m)
		}
		if _, ok := m["DNSSEC_DOMAINS"]; ok {
			t.Fatalf("per-zone invocation must not carry DNSSEC_DOMAINS: %v", m)
		}
		if _, ok := m["DNSSEC_BATCH_SIZE"]; ok {
			t.Fatalf("per-zone invocation must not carry DNSSEC_BATCH_SIZE: %v", m)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("per-zone invocations for %v, want %v", got, want)
	}
}

// assertBatch checks exactly one batch invocation naming the expected domains.
func (z *cliZones) assertBatch(t *testing.T, inv []map[string]string, want ...string) {
	t.Helper()
	if len(inv) != 1 {
		t.Fatalf("expected one batch invocation, got %d: %v", len(inv), inv)
	}
	m := inv[0]
	got := strings.Fields(m["DNSSEC_DOMAINS"])
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") || m["DNSSEC_BATCH_SIZE"] != strconv.Itoa(len(want)) || m["DNSSEC_OUTPUT_DIR"] != z.cfg.OutputDir {
		t.Fatalf("batch variables wrong: %v (want %v)", m, want)
	}
	if _, ok := m["DNSSEC_DOMAIN"]; ok {
		t.Fatalf("batch invocation must not carry DNSSEC_DOMAIN: %v", m)
	}
}

func TestCLISign_HookContract(t *testing.T) {
	for _, coalesce := range []bool{false, true} {
		t.Run(fmt.Sprintf("coalesce=%v", coalesce), func(t *testing.T) {
			z := newCLIZones(t, coalesce, "a.example", "b.example", "c.example")
			if err := runSign(nil, nil); err != nil {
				t.Fatalf("sign: %v", err)
			}
			inv := z.recorder.invocations(t)
			if coalesce {
				z.assertBatch(t, inv, "a.example", "b.example", "c.example")
			} else {
				z.assertPerZone(t, inv, "a.example", "b.example", "c.example")
			}

			// Mixed failure: only the zones that signed are handed to the hook.
			z.recorder.reset()
			if err := os.WriteFile(z.zones["b.example"], []byte("not a zone\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := runSign(nil, nil); err == nil {
				t.Fatal("sign with a failing zone must exit non-zero")
			}
			inv = z.recorder.invocations(t)
			if coalesce {
				z.assertBatch(t, inv, "a.example", "c.example")
			} else {
				z.assertPerZone(t, inv, "a.example", "c.example")
			}

			// Zero successful zones: no invocation at all.
			z.recorder.reset()
			for _, d := range []string{"a.example", "c.example"} {
				if err := os.WriteFile(z.zones[d], []byte("not a zone\n"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			_ = runSign(nil, nil)
			if inv := z.recorder.invocations(t); len(inv) != 0 {
				t.Fatalf("no zone signed, but the hook ran: %v", inv)
			}
		})
	}
}

func TestCLISingleZoneCommands_HookContract(t *testing.T) {
	for _, coalesce := range []bool{false, true} {
		t.Run(fmt.Sprintf("coalesce=%v", coalesce), func(t *testing.T) {
			z := newCLIZones(t, coalesce, "r.example")
			check := func(t *testing.T, what, domain string) {
				t.Helper()
				inv := z.recorder.invocations(t)
				if coalesce {
					z.assertBatch(t, inv, domain)
				} else {
					z.assertPerZone(t, inv, domain)
				}
				z.recorder.reset()
			}

			if err := runResign(nil, []string{"r.example"}); err != nil {
				t.Fatal(err)
			}
			check(t, "resign", "r.example")

			// add
			addZone := filepath.Join(z.dir, "added.example.zone")
			if err := os.WriteFile(addZone, []byte(validZoneContent("added.example")), 0644); err != nil {
				t.Fatal(err)
			}
			z.zones["added.example"] = addZone
			if err := runAdd(nil, []string{"added.example", addZone}); err != nil {
				t.Fatal(err)
			}
			check(t, "add", "added.example")

			// import
			kskBase, zskBase, _, _ := sourceKeys(t, "imported.example")
			impZone := filepath.Join(z.dir, "imported.example.zone")
			if err := os.WriteFile(impZone, []byte(validZoneContent("imported.example")), 0644); err != nil {
				t.Fatal(err)
			}
			z.zones["imported.example"] = impZone
			cmd := &cobra.Command{}
			cmd.Flags().String("ksk", kskBase, "")
			cmd.Flags().String("zsk", zskBase, "")
			if err := runImport(cmd, []string{"imported.example", impZone}); err != nil {
				t.Fatal(err)
			}
			check(t, "import", "imported.example")

			// rollover start
			if err := runRolloverStart(nil, []string{"r.example"}); err != nil {
				t.Fatal(err)
			}
			check(t, "rollover start", "r.example")
		})
	}
}

// A failing hook on `sign` is reported through the exit status while the
// zones stay signed.
func TestCLISign_HookFailureIsReported(t *testing.T) {
	z := newCLIZones(t, false, "f.example")
	content, _ := os.ReadFile(z.cfgPath)
	failing := strings.Replace(string(content), z.recorder.cmd()[2], "exit 7", 1)
	if err := os.WriteFile(z.cfgPath, []byte(failing), 0600); err != nil {
		t.Fatal(err)
	}
	err := runSign(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "post-sign hook failed") {
		t.Fatalf("hook failure must be reported, got %v", err)
	}
	if _, serr := os.Stat(z.signedPath("f.example")); serr != nil {
		t.Fatal("zone must still be signed")
	}
}
