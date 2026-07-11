package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReload_TickerResetLatestWins (R-057): two rapid reloads that both change
// the poll interval must leave the ticker on the LATEST interval, not keep the
// first and drop the second.
func TestReload_TickerResetLatestWins(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig(t, dir)
	cfg.Heartbeat.Enabled = false
	cfg.PollInterval = Duration{5 * time.Minute}
	state := NewState(cfg.StatePath())
	d := NewDaemon(cfg, state)

	cfg1 := *cfg
	cfg1.PollInterval = Duration{1 * time.Minute}
	cfg2 := *cfg
	cfg2.PollInterval = Duration{2 * time.Minute}

	// Nobody drains tickerReset between these two reloads.
	d.Reload(&cfg1, state)
	d.Reload(&cfg2, state)

	select {
	case got := <-d.tickerReset:
		if got != 2*time.Minute {
			t.Errorf("tickerReset should hold the latest interval; got %v want 2m", got)
		}
	default:
		t.Fatal("expected a tickerReset value after the reloads")
	}
}

// TestSetupLogging_ReopensFileOnRerun (R-056): re-running setupLogging (what
// SIGHUP now does) reopens the log path, so logrotate (rename + SIGHUP) doesn't
// leave the daemon writing to the unlinked fd.
func TestSetupLogging_ReopensFileOnRerun(t *testing.T) {
	origLevel, origFormat, origOutput, origFile := logLevel, logFormat, logOutput, logFile
	origDefault := slog.Default()
	t.Cleanup(func() {
		if logFile != nil && logFile != origFile {
			logFile.Close()
		}
		logLevel, logFormat, logOutput, logFile = origLevel, origFormat, origOutput, origFile
		slog.SetDefault(origDefault)
	})

	dir := t.TempDir()
	logPath := filepath.Join(dir, "daemon.log")
	logLevel, logFormat, logOutput = "info", "text", logPath

	setupLogging()
	slog.Info("first line")

	// Simulate logrotate renaming the active file away.
	if err := os.Rename(logPath, logPath+".1"); err != nil {
		t.Fatal(err)
	}

	// Re-run setupLogging (the SIGHUP reopen) → a fresh file at the original path.
	setupLogging()
	slog.Info("second line")

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("reopened log was not created at the original path: %v", err)
	}
	if !strings.Contains(string(data), "second line") {
		t.Errorf("second line not written to the reopened log: %q", data)
	}
	rotated, err := os.ReadFile(logPath + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rotated), "first line") {
		t.Errorf("first line should be in the rotated file: %q", rotated)
	}
}
