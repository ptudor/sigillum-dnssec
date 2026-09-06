package config

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDurationUnmarshalText_RejectsTrailingGarbage (R-053): the year/month/day
// numeric prefix must be a complete float, so "1x2d" is a parse error rather
// than silently truncating to 1 day.
func TestDurationUnmarshalText_RejectsTrailingGarbage(t *testing.T) {
	var d Duration
	if err := d.UnmarshalText([]byte("1x2d")); err == nil {
		t.Errorf(`"1x2d" must be a parse error, got %v`, d.Duration)
	}

	valid := []struct {
		in   string
		want time.Duration
	}{
		{"5d", 5 * 24 * time.Hour},
		{"1y", 365 * 24 * time.Hour},
		{"2M", 2 * 30 * 24 * time.Hour},
		{"1.5d", 36 * time.Hour},
		{"90s", 90 * time.Second},
		{"5m", 5 * time.Minute},
	}
	for _, c := range valid {
		var dd Duration
		if err := dd.UnmarshalText([]byte(c.in)); err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
		} else if dd.Duration != c.want {
			t.Errorf("%q = %v, want %v", c.in, dd.Duration, c.want)
		}
	}
}

// TestWarnIfConfigWorldReadable (R-052): a secrets-bearing config that is more
// permissive than 0640 gets a warning; a 0640 config, or a loose config with no
// secrets, does not.
func TestWarnIfConfigWorldReadable(t *testing.T) {
	withCapturedLog := func(t *testing.T, fn func()) string {
		t.Helper()
		var buf bytes.Buffer
		prev := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
		defer slog.SetDefault(prev)
		fn()
		return buf.String()
	}

	writeCfg := func(t *testing.T, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(p, []byte("x=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	secretCfg := &Config{}
	secretCfg.Registrar.Dynadot.APIKey = "some-key"
	noSecretCfg := &Config{}

	t.Run("world-readable with secrets warns", func(t *testing.T) {
		p := writeCfg(t, 0o644)
		out := withCapturedLog(t, func() { warnIfConfigWorldReadable(p, secretCfg) })
		if !strings.Contains(out, "more permissive than 0640") {
			t.Errorf("expected a permission warning, got: %q", out)
		}
	})

	t.Run("0640 with secrets is quiet", func(t *testing.T) {
		p := writeCfg(t, 0o640)
		out := withCapturedLog(t, func() { warnIfConfigWorldReadable(p, secretCfg) })
		if strings.Contains(out, "more permissive") {
			t.Errorf("0640 must not warn, got: %q", out)
		}
	})

	t.Run("world-readable without secrets is quiet", func(t *testing.T) {
		p := writeCfg(t, 0o644)
		out := withCapturedLog(t, func() { warnIfConfigWorldReadable(p, noSecretCfg) })
		if strings.Contains(out, "more permissive") {
			t.Errorf("no-secrets config must not warn, got: %q", out)
		}
	})
}
