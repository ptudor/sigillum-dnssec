//go:build !windows

package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-031: `resign` and `import` exit non-zero with a distinct error
// when the committed signing/import is followed by a failed deployment hook,
// preserving every committed file and the pending-publication marker and
// never claiming unqualified success; a successful hook, or no hook, keeps
// the existing successful exit.

// captureStdout runs fn with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

func TestRDAYBLUEX031_ResignFailedHookIsANonZeroExit(t *testing.T) {
	z := newCLIZones(t, false, "r.example")
	// Replace the recorder hook with a failing one in the config file.
	data, err := os.ReadFile(z.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	failing := strings.Replace(string(data), z.recorder.cmd()[2], "exit 7", 1)
	if err := os.WriteFile(z.cfgPath, []byte(failing), 0o600); err != nil {
		t.Fatal(err)
	}

	var runErr error
	out := captureStdout(t, func() { runErr = runResign(nil, []string{"r.example"}) })
	if !errors.Is(runErr, ErrDeploymentNotConfirmed) {
		t.Fatalf("resign after a failed hook must return the distinct deployment error, got %v", runErr)
	}
	if strings.Contains(out, "successfully") {
		t.Fatalf("stdout must not claim unqualified success:\n%s", out)
	}
	if !strings.Contains(out, "NOT confirmed served") || !strings.Contains(out, "re-signed") {
		t.Fatalf("stdout must distinguish signed from confirmed served:\n%s", out)
	}
	// Committed and pending, with the deployment error persisted.
	if _, err := os.Stat(z.signedPath("r.example")); err != nil {
		t.Fatalf("the signed output must remain committed: %v", err)
	}
	disk, err := statepkg.LoadState(z.cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	zs := disk.GetZone("r.example")
	if zs.LastSigned.IsZero() || !zs.PendingPublication || !hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("state must show a committed, pending generation with the deployment error: %+v", zs)
	}

	// Heal the hook: the retry succeeds and exits zero.
	if err := os.WriteFile(z.cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() { runErr = runResign(nil, []string{"r.example"}) })
	if runErr != nil {
		t.Fatalf("resign with a healthy hook must succeed: %v", runErr)
	}
	if !strings.Contains(out, "confirmed served") {
		t.Fatalf("a confirmed deployment must be reported:\n%s", out)
	}
	disk, _ = statepkg.LoadState(z.cfg.StatePath())
	if zs := disk.GetZone("r.example"); zs.PendingPublication || hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("the retried deployment must confirm and clear the error: %+v", zs)
	}
}

func TestRDAYBLUEX031_ResignWithoutHookStillSucceeds(t *testing.T) {
	z := newCLIZones(t, false, "n.example")
	data, _ := os.ReadFile(z.cfgPath)
	noHook := string(data)[:strings.Index(string(data), "[hooks]")] + string(data)[strings.Index(string(data), "[zones."):]
	if err := os.WriteFile(z.cfgPath, []byte(noHook), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runResign(nil, []string{"n.example"}); err != nil {
		t.Fatalf("resign without a hook (immediate mode) must succeed: %v", err)
	}
}

func TestRDAYBLUEX031_ImportFailedHookIsANonZeroExit(t *testing.T) {
	f := newImportFixture(t, "imp.example")
	content := "output_dir = \"" + f.dir + "/signed\"\ndata_dir = \"" + f.dir + "\"\n\n[hooks]\npost_sign_cmd = [\"/bin/sh\", \"-c\", \"exit 3\"]\n"
	if err := os.WriteFile(f.cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var runErr error
	out := captureStdout(t, func() { runErr = f.run(t) })
	if !errors.Is(runErr, ErrDeploymentNotConfirmed) {
		t.Fatalf("import after a failed hook must return the distinct deployment error, got %v", runErr)
	}
	if strings.Contains(out, "successfully") || !strings.Contains(out, "NOT confirmed served") {
		t.Fatalf("stdout must not claim unqualified success and must report the deployment:\n%s", out)
	}
	// Fully committed: keys, output, state (pending) and config.
	if _, err := os.Stat(f.outputPath()); err != nil {
		t.Fatalf("the signed output must remain committed: %v", err)
	}
	disk, err := statepkg.LoadState(f.dir + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	zs := disk.GetZone(f.domain)
	if zs == nil || zs.KSK == nil || zs.KSK.ID != f.kskTag || !zs.PendingPublication || !hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("state must show the committed, pending import with the deployment error: %+v", zs)
	}
	cfgData, _ := os.ReadFile(f.cfgPath)
	if !strings.Contains(string(cfgData), f.domain) {
		t.Fatal("the config entry must remain committed")
	}
}
