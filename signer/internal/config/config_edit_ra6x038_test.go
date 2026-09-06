package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func writeCfg(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustParse(t *testing.T, p string) *Config {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := decodeConfig(data)
	if err != nil {
		t.Fatalf("%s is not valid strict TOML: %v", p, err)
	}
	return cfg
}

// assertUnrelatedEqual fails if anything but the zones map differs between two
// parsed configurations, or if any zone other than domain differs.
func assertUnrelatedEqual(t *testing.T, before, after *Config, domain string) {
	t.Helper()
	b, a := *before, *after
	b.Zones, a.Zones = nil, nil
	b.LoadedAt, a.LoadedAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(b, a) {
		t.Fatalf("unrelated configuration changed:\nbefore %+v\nafter  %+v", b, a)
	}
	for name, zc := range before.Zones {
		if name == domain {
			continue
		}
		if !reflect.DeepEqual(after.Zones[name], zc) {
			t.Fatalf("unrelated zone %q changed", name)
		}
	}
}

// The review's first probe: a multi-line literal hook string containing a line
// that looks exactly like the zone's table header, followed by the real table.
// Removal must delete only the real table and leave valid TOML with the hook
// string intact.
func TestRemoveZone_IgnoresHeaderInsideMultilineLiteralString(t *testing.T) {
	const content = `output_dir = "/var/signed"
data_dir = "/var/lib"

[hooks]
post_sign = '''
[zones."example.com"]
printf hello
'''

[zones."example.com"]
path = "/zones/example.db"

[zones."keep.example"]
path = "/zones/keep.db"
`
	p := writeCfg(t, content)
	before := mustParse(t, p)
	if err := RemoveZoneFromConfigFile(p, "example.com"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	after := mustParse(t, p)
	if _, ok := after.Zones["example.com"]; ok {
		t.Fatal("zone must be removed")
	}
	assertUnrelatedEqual(t, before, after, "example.com")
	if after.Hooks.PostSign != "[zones.\"example.com\"]\nprintf hello\n" {
		t.Fatalf("hook string changed: %q", after.Hooks.PostSign)
	}
	out, _ := os.ReadFile(p)
	if !strings.Contains(string(out), "printf hello\n'''") {
		t.Fatalf("multi-line string terminator must survive:\n%s", out)
	}
}

// The same with a multi-line basic string, an escaped delimiter inside it and a
// closing delimiter carrying an extra quote.
func TestRemoveZone_IgnoresHeaderInsideMultilineBasicString(t *testing.T) {
	const content = `output_dir = "/var/signed"
data_dir = "/var/lib"

[hooks]
post_sign = """
[zones."target.example"]
echo \"""not closed here
[[registrar.extra]]
done""""

[zones."target.example"]
path = "/zones/target.db"
[zones."next.example"] # keep
path = "/zones/next.db"
`
	p := writeCfg(t, content)
	before := mustParse(t, p)
	if err := RemoveZoneFromConfigFile(p, "target.example"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	after := mustParse(t, p)
	if _, ok := after.Zones["target.example"]; ok {
		t.Fatal("zone must be removed")
	}
	assertUnrelatedEqual(t, before, after, "target.example")
	if !strings.Contains(after.Hooks.PostSign, "[[registrar.extra]]") || !strings.HasSuffix(after.Hooks.PostSign, `done"`) {
		t.Fatalf("hook string changed: %q", after.Hooks.PostSign)
	}
	if _, ok := after.Zones["next.example"]; !ok {
		t.Fatal("following zone must survive")
	}
}

// The review's second probe: a source path containing a control byte. Go's %q
// wrote \a, which TOML rejects; the value must round-trip through TOML.
func TestAddZone_TOMLCompatibleEscaping(t *testing.T) {
	paths := []string{
		"/zones/bell\a.db",
		"/zones/with \"quotes\" and \\backslash.db",
		"/zones/tab\tnewline\ncr\r.db",
		"/zones/unicodé/зона.db",
		"/zones/del\x7f.db",
	}
	for _, zp := range paths {
		p := writeCfg(t, "output_dir = \"/var/signed\"\ndata_dir = \"/var/lib\"\n")
		before := mustParse(t, p)
		if err := AddZoneToConfigFile(p, "esc.example", zp); err != nil {
			t.Fatalf("add %q: %v", zp, err)
		}
		after := mustParse(t, p)
		if got := after.Zones["esc.example"].Path; got != zp {
			t.Fatalf("path round-trip: got %q want %q", got, zp)
		}
		assertUnrelatedEqual(t, before, after, "esc.example")
		if err := RemoveZoneFromConfigFile(p, "esc.example"); err != nil {
			t.Fatalf("remove %q: %v", zp, err)
		}
		if _, ok := mustParse(t, p).Zones["esc.example"]; ok {
			t.Fatal("zone must be removed again")
		}
	}
	// Invalid UTF-8 cannot be represented in TOML and is refused without a write.
	p := writeCfg(t, "output_dir = \"/var/signed\"\n")
	orig, _ := os.ReadFile(p)
	if err := AddZoneToConfigFile(p, "bad.example", "/zones/\xff.db"); err == nil {
		t.Fatal("invalid UTF-8 path must be refused")
	}
	if now, _ := os.ReadFile(p); !bytes.Equal(orig, now) {
		t.Fatal("refused add must leave the file untouched")
	}
}

// Commented headers, spaced/dotted syntax, literal keys, escapes in keys and a
// final table without a trailing newline are all handled.
func TestRemoveZone_HeaderSpellings(t *testing.T) {
	headers := []string{
		`[zones."b.example"]`,
		`[ zones . "b.example" ]`,
		`[zones.'b.example']`,
		`[ zones.'b.example' ]   # comment`,
		"\t[zones . \"b.example\"]",
		`[zones."b.\u0065xample"]`,
	}
	for _, h := range headers {
		t.Run(h, func(t *testing.T) {
			content := "output_dir = \"/var/signed\"\ndata_dir = \"/var/lib\"\n\n# [zones.\"b.example\"] commented out, must stay\n[zones.\"a.example\"]\npath = \"C:\\\\zones\\\\a.db\"\n\n" + h + "\npath = \"/zones/b.db\"\n\n[zones.\"c.example\"]\npath = \"/zones/c.db\""
			p := writeCfg(t, content)
			before := mustParse(t, p)
			if err := RemoveZoneFromConfigFile(p, "b.example"); err != nil {
				t.Fatalf("remove with %q: %v", h, err)
			}
			after := mustParse(t, p)
			if _, ok := after.Zones["b.example"]; ok {
				t.Fatal("zone must be removed")
			}
			assertUnrelatedEqual(t, before, after, "b.example")
			out, _ := os.ReadFile(p)
			for _, keep := range []string{"# [zones.\"b.example\"] commented out", `path = "C:\\zones\\a.db"`, `[zones."c.example"]`} {
				if !strings.Contains(string(out), keep) {
					t.Fatalf("%q must survive:\n%s", keep, out)
				}
			}
			if after.Zones["a.example"].Path != `C:\zones\a.db` {
				t.Fatalf("escaped path changed: %q", after.Zones["a.example"].Path)
			}
		})
	}
}

// Removing the final table of a file with no trailing newline, and adding to
// such a file, both produce valid TOML.
func TestZoneEdit_FinalTableWithoutTrailingNewline(t *testing.T) {
	p := writeCfg(t, "output_dir = \"/var/signed\"\n[zones.\"a.example\"]\npath = \"/zones/a.db\"\n[zones.\"last.example\"]\npath = \"/zones/last.db\"")
	if err := RemoveZoneFromConfigFile(p, "last.example"); err != nil {
		t.Fatal(err)
	}
	after := mustParse(t, p)
	if _, ok := after.Zones["last.example"]; ok || after.Zones["a.example"].Path != "/zones/a.db" {
		t.Fatalf("unexpected zones %+v", after.Zones)
	}
	p = writeCfg(t, "output_dir = \"/var/signed\"\n[zones.\"a.example\"]\npath = \"/zones/a.db\"")
	if err := AddZoneToConfigFile(p, "new.example", "/zones/new.db"); err != nil {
		t.Fatal(err)
	}
	after = mustParse(t, p)
	if after.Zones["new.example"].Path != "/zones/new.db" || after.Zones["a.example"].Path != "/zones/a.db" {
		t.Fatalf("unexpected zones %+v", after.Zones)
	}
}

// A candidate that does not parse, or whose change is not limited to the
// intended zone, never replaces the original.
func TestValidateZoneEdit_RefusesBadCandidates(t *testing.T) {
	orig := []byte("output_dir = \"/var/signed\"\n\n[zones.\"a.example\"]\npath = \"/zones/a.db\"\n\n[zones.\"b.example\"]\npath = \"/zones/b.db\"\n")
	cases := map[string]struct {
		candidate string
		domain    string
		want      *ZoneConfig
	}{
		"unparseable":          {"output_dir = \"/var/signed\"\n[zones.\"a.example\"\npath = \"/zones/a.db\"\n", "b.example", nil},
		"drops another zone":   {"output_dir = \"/var/signed\"\n\n[zones.\"a.example\"]\npath = \"/zones/a.db\"\n", "c.example", nil},
		"changes a setting":    {"output_dir = \"/elsewhere\"\n\n[zones.\"a.example\"]\npath = \"/zones/a.db\"\n", "b.example", nil},
		"zone still present":   {string(orig), "b.example", nil},
		"zone not as intended": {string(orig) + "\n[zones.\"c.example\"]\npath = \"/other.db\"\n", "c.example", &ZoneConfig{Path: "/zones/c.db"}},
	}
	for name, tc := range cases {
		if err := validateZoneEdit(orig, []byte(tc.candidate), tc.domain, tc.want); err == nil {
			t.Errorf("%s: candidate must be refused", name)
		}
	}
	if err := validateZoneEdit(orig, []byte("output_dir = \"/var/signed\"\n\n[zones.\"a.example\"]\npath = \"/zones/a.db\"\n"), "b.example", nil); err != nil {
		t.Errorf("a correct removal must pass: %v", err)
	}
}

// Whole-flow: a zone whose table is followed by a sub-table of its own
// ([zones."d".extra]) would survive the table's line-range removal, so the
// removal is refused and the file is left byte-for-byte intact.
func TestRemoveZone_RefusesWhenZoneWouldSurvive(t *testing.T) {
	content := "output_dir = \"/var/signed\"\n\n[zones.\"dup.example\"]\npath = \"/zones/dup.db\"\n\n[zones.\"dup.example\".extra]\nnote = \"x\"\n"
	p := writeCfg(t, content)
	err := RemoveZoneFromConfigFile(p, "dup.example")
	if err == nil || !strings.Contains(err.Error(), "still be configured") {
		t.Fatalf("removal must be refused, got %v", err)
	}
	now, _ := os.ReadFile(p)
	if string(now) != content {
		t.Fatal("refused edit must leave the original bytes intact")
	}
}

// Unrelated tables this program does not know (rejected by the strict loader)
// are preserved exactly through an edit of a file that otherwise parses.
func TestZoneEdit_PreservesUnknownTables(t *testing.T) {
	content := "output_dir = \"/var/signed\"\n\n[zones.\"a.example\"]\npath = \"/zones/a.db\"\n\n[[future.items]]\nname = \"one\"\n[[future.items]]\nname = \"two\"\n"
	p := writeCfg(t, content)
	if err := RemoveZoneFromConfigFile(p, "a.example"); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(p)
	if !strings.Contains(string(out), "[[future.items]]\nname = \"one\"\n[[future.items]]\nname = \"two\"") {
		t.Fatalf("unknown tables must survive:\n%s", out)
	}
	if strings.Contains(string(out), "a.example") {
		t.Fatal("zone must be removed")
	}
}

func TestParseTableHeader(t *testing.T) {
	cases := []struct {
		line  string
		path  []string
		array bool
		ok    bool
	}{
		{`[zones."a.b"]`, []string{"zones", "a.b"}, false, true},
		{`[ zones . 'a.b' ] # c`, []string{"zones", "a.b"}, false, true},
		{`[zones.example]`, []string{"zones", "example"}, false, true},
		{`[zones.a.b]`, []string{"zones", "a", "b"}, false, true},
		{`[[registrar.extra]]`, []string{"registrar", "extra"}, true, true},
		{`[zones."a\"b"]`, []string{"zones", `a"b`}, false, true},
		{`[zones."a\u0062c"]`, []string{"zones", "abc"}, false, true},
		{`[zones."a"] path = 1`, nil, false, false},
		{`[zones."unterminated]`, nil, false, false},
		{`[[zones."x"]`, nil, false, false},
		{`[zones..x]`, nil, false, false},
		{`[]`, nil, false, false},
		{`key = "[x]"`, nil, false, false},
		{`# [zones."x"]`, nil, false, false},
	}
	for _, tc := range cases {
		path, array, ok := parseTableHeader(tc.line)
		if ok != tc.ok || array != tc.array || !reflect.DeepEqual(path, tc.path) {
			t.Errorf("parseTableHeader(%q) = %v,%v,%v want %v,%v,%v", tc.line, path, array, ok, tc.path, tc.array, tc.ok)
		}
	}
	if !IsZoneTableHeader(`[zones.example]`, "example") || IsZoneTableHeader(`[[zones."x"]]`, "x") {
		t.Error("bare single-label key must match; array-of-tables must not")
	}
}

func TestScanTOMLLine_Context(t *testing.T) {
	lines := []string{
		`a = "x # not a comment" # comment`,
		`b = """`,
		`[zones."inside"]`,
		`still \""" inside`,
		`closed """" c = 1`,
		`[zones."real"]`,
		`d = '''`,
		`[zones."inside2"]`,
		`'''`,
		`e = ''''''`,
		`[zones."after"]`,
	}
	got := tomlHeaderPositions(lines)
	want := []bool{true, true, false, false, false, true, true, false, false, true, true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("header positions %v, want %v", got, want)
	}
}

func TestTOMLBasicString(t *testing.T) {
	got, err := tomlBasicString("a\"b\\c\td\ne\a\x7f")
	if err != nil {
		t.Fatal(err)
	}
	if want := `"a\"b\\c\td\ne\u0007\u007F"`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if _, err := tomlBasicString("\xff"); err == nil {
		t.Fatal("invalid UTF-8 must be refused")
	}
}
