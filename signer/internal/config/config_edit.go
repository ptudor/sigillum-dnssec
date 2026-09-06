package config

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
	"github.com/ptudor/sigillum-dnssec/signer/internal/fsutil"
)

// Zone-table edits to the configuration file (RA6X-038).
//
// `add`/`import` append a [zones."<domain>"] table and `remove` deletes one,
// preserving every other byte of the operator's file — comments, ordering,
// formatting. To make that safe on real TOML the editor (1) recognizes table
// headers only where TOML syntax allows one, tracking multi-line basic and
// literal strings across lines so a header-looking line inside a hook script
// is never mistaken for a table; (2) parses headers with the TOML key grammar
// (whitespace, dotted, bare, basic and literal keys, escapes, inline comment);
// (3) serializes new values as TOML basic strings; and (4) before replacing the
// file, parses the candidate with the same strict decoder LoadConfig uses and
// asserts that its only semantic change is the intended zone. Any failure
// leaves the original bytes untouched.

// ErrZoneNotInConfig is returned by RemoveZoneFromConfigFile when the zone table is absent.
var ErrZoneNotInConfig = fmt.Errorf("zone table not found in config file")

// AddZoneToConfigFile appends a [zones."<domain>"] table with the zone's path.
// The candidate file is parsed and checked to differ from the original only by
// that zone before it atomically replaces the file (ownership and mode
// preserved).
func AddZoneToConfigFile(configPath, domain, zonePath string) error {
	existing, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}

	key, err := tomlBasicString(domain)
	if err != nil {
		return fmt.Errorf("zone name: %w", err)
	}
	value, err := tomlBasicString(zonePath)
	if err != nil {
		return fmt.Errorf("zone path: %w", err)
	}

	// Append the new zone section, matching the previous formatting (a leading blank
	// line before the table). Ensure exactly one separating newline regardless of
	// whether the file already ends in one.
	buf := make([]byte, 0, len(existing)+128)
	buf = append(buf, existing...)
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		buf = append(buf, '\n')
	}
	buf = append(buf, []byte(fmt.Sprintf("\n[zones.%s]\npath = %s\n", key, value))...)

	if err := validateZoneEdit(existing, buf, domain, &ZoneConfig{Path: zonePath}); err != nil {
		return err
	}
	if err := fsutil.WriteConfigFileAtomic(configPath, buf); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}
	return nil
}

// RemoveZoneFromConfigFile deletes the [zones."<domain>"] table (its header and
// every line up to the next table header that is outside any multi-line string)
// from the config file, preserving all other content and comments. The
// candidate is parsed and checked to differ from the original only by that
// zone before it atomically replaces the file (ownership and mode preserved).
// Returns ErrZoneNotInConfig if no such table header is present, so the caller
// can proceed.
func RemoveZoneFromConfigFile(configPath, domain string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	headerable := tomlHeaderPositions(lines)

	start := -1
	for i, line := range lines {
		if headerable[i] && IsZoneTableHeader(line, domain) {
			start = i
			break
		}
	}
	if start == -1 {
		return ErrZoneNotInConfig
	}

	// The table runs until the next TOML table header (outside any multi-line
	// string) or EOF.
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if headerable[i] && isTOMLTableHeader(lines[i]) {
			end = i
			break
		}
	}

	// Absorb one blank line immediately preceding the table (AddZoneToConfigFile prefixes
	// one) so repeated add/remove cycles don't accumulate blank runs.
	removeStart := start
	if removeStart > 0 && strings.TrimSpace(lines[removeStart-1]) == "" {
		removeStart--
	}

	kept := make([]string, 0, len(lines)-(end-removeStart))
	kept = append(kept, lines[:removeStart]...)
	kept = append(kept, lines[end:]...)
	candidate := []byte(strings.Join(kept, "\n"))

	if err := validateZoneEdit(data, candidate, domain, nil); err != nil {
		return err
	}
	// R-002: use the config-specific atomic writer, which preserves the config's
	// OWN uid/gid/mode. writeFileAtomicOwned would chown the (root-owned, secrets-
	// bearing) config to the daemon account.
	if err := fsutil.WriteConfigFileAtomic(configPath, candidate); err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}
	return nil
}

// validateZoneEdit parses the original and the candidate as generic TOML and
// requires that the candidate's only semantic change is zone `domain`: present
// with exactly `want` after an add, absent after a remove (want == nil). Every
// other table, key and value — including ones this program does not know —
// must be unchanged. An original that loads under the strict LoadConfig rules
// must still load after the edit. The original bytes are never replaced when
// this fails.
func validateZoneEdit(original, candidate []byte, domain string, want *ZoneConfig) error {
	var origTree, candTree map[string]any
	if err := toml.Unmarshal(original, &origTree); err != nil {
		return fmt.Errorf("refusing to edit a configuration file that does not parse (left unchanged): %w", err)
	}
	if err := toml.Unmarshal(candidate, &candTree); err != nil {
		return fmt.Errorf("the edited configuration would not parse (original left unchanged): %w", err)
	}

	candZone, candHas := detachZone(candTree, domain)
	detachZone(origTree, domain)
	if !reflect.DeepEqual(origTree, candTree) {
		return fmt.Errorf("the edit would change configuration outside zone %q (original left unchanged)", domain)
	}
	switch {
	case want == nil && candHas:
		return fmt.Errorf("zone %q would still be configured after the edit — it is also defined outside its table (original left unchanged)", domain)
	case want != nil && (!candHas || !reflect.DeepEqual(candZone, map[string]any{"path": want.Path})):
		return fmt.Errorf("zone %q would not be configured as intended after the edit (original left unchanged)", domain)
	}

	if _, err := ParseConfig(original); err == nil {
		if _, err := ParseConfig(candidate); err != nil {
			return fmt.Errorf("the edited configuration would not load (original left unchanged): %w", err)
		}
	}
	return nil
}

// detachZone removes zones.<domain> from a generic TOML tree and returns it.
// An emptied zones table is dropped so "no zones" compares equal whether or
// not the table header remains.
func detachZone(tree map[string]any, domain string) (any, bool) {
	zones, ok := tree["zones"].(map[string]any)
	if !ok {
		return nil, false
	}
	entry, has := zones[domain]
	delete(zones, domain)
	if len(zones) == 0 {
		delete(tree, "zones")
	}
	return entry, has
}

// tomlBasicString renders s as a TOML basic string: quotes and backslashes
// escaped, control characters as the short escapes TOML defines or \uXXXX.
// TOML requires valid UTF-8, so a byte sequence that is not cannot be
// represented and is refused.
func tomlBasicString(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%q is not valid UTF-8 and cannot be written to a TOML file", s)
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\u%04X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String(), nil
}

// tomlScanState is the multi-line string context carried across lines.
type tomlScanState int

const (
	tomlNormal       tomlScanState = iota
	tomlMultiBasic                 // inside """..."""
	tomlMultiLiteral               // inside '''...'''
)

// tomlHeaderPositions reports, for each line, whether it begins outside any
// multi-line string — the only positions where a table header can occur.
func tomlHeaderPositions(lines []string) []bool {
	state := tomlNormal
	out := make([]bool, len(lines))
	for i, line := range lines {
		out[i] = state == tomlNormal
		state = scanTOMLLine(line, state)
	}
	return out
}

// scanTOMLLine advances the multi-line string state across one line. Inside a
// multi-line basic string a backslash escapes the next character (so \""" does
// not close it and a line-ending backslash continues the string); a closing
// delimiter may carry up to two extra quotes that belong to the content.
// Outside strings, single-line basic/literal strings are skipped so quotes and
// hashes inside them are not misread, and # starts a comment.
func scanTOMLLine(line string, state tomlScanState) tomlScanState {
	n := len(line)
	i := 0
	for i < n {
		switch state {
		case tomlMultiBasic:
			if line[i] == '\\' {
				i += 2
				continue
			}
			if strings.HasPrefix(line[i:], `"""`) {
				j := i + 3
				for j < n && j < i+5 && line[j] == '"' {
					j++
				}
				state, i = tomlNormal, j
				continue
			}
			i++
		case tomlMultiLiteral:
			if strings.HasPrefix(line[i:], `'''`) {
				j := i + 3
				for j < n && j < i+5 && line[j] == '\'' {
					j++
				}
				state, i = tomlNormal, j
				continue
			}
			i++
		default:
			switch {
			case line[i] == '#':
				return state
			case strings.HasPrefix(line[i:], `"""`):
				state, i = tomlMultiBasic, i+3
			case strings.HasPrefix(line[i:], `'''`):
				state, i = tomlMultiLiteral, i+3
			case line[i] == '"':
				i++
				for i < n && line[i] != '"' {
					if line[i] == '\\' {
						i++
					}
					i++
				}
				i++
			case line[i] == '\'':
				i++
				for i < n && line[i] != '\'' {
					i++
				}
				i++
			default:
				i++
			}
		}
	}
	return state
}

// IsZoneTableHeader reports whether a config line is the table header for
// zone `domain`: a standard (not array-of-tables) header whose key path is
// exactly zones.<domain>, in any TOML spelling — `[zones."d"]` as written by
// AddZoneToConfigFile, a literal-string key, a bare key for a single-label
// name, whitespace inside the brackets or around the dot, escapes inside the
// key, and a trailing inline comment. Callers must only apply it to lines
// that start outside a multi-line string (see tomlHeaderPositions).
func IsZoneTableHeader(line, domain string) bool {
	path, array, ok := parseTableHeader(line)
	return ok && !array && len(path) == 2 && path[0] == "zones" && path[1] == domain
}

// isTOMLTableHeader reports whether a line is a TOML table header — a normal
// table "[...]" or an array-of-tables "[[...]]" — with any valid key syntax and
// an optional trailing inline comment.
func isTOMLTableHeader(line string) bool {
	_, _, ok := parseTableHeader(line)
	return ok
}

// parseTableHeader parses a line as a TOML table header and returns its key
// path (each segment unquoted/unescaped) and whether it is an array-of-tables
// header. ok is false for anything that is not a syntactically valid header
// optionally followed by whitespace and a comment.
func parseTableHeader(line string) (path []string, array bool, ok bool) {
	t := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(t, "[") {
		return nil, false, false
	}
	i := 1
	if strings.HasPrefix(t, "[[") {
		array = true
		i = 2
	}
	for {
		i = skipBlanks(t, i)
		seg, next, segOK := parseKeySegment(t, i)
		if !segOK {
			return nil, false, false
		}
		path = append(path, seg)
		i = skipBlanks(t, next)
		if i >= len(t) {
			return nil, false, false
		}
		if t[i] == '.' {
			i++
			continue
		}
		if t[i] != ']' {
			return nil, false, false
		}
		i++
		if array {
			if i >= len(t) || t[i] != ']' {
				return nil, false, false
			}
			i++
		}
		rest := strings.TrimSpace(t[i:])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return nil, false, false
		}
		return path, array, true
	}
}

func skipBlanks(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// parseKeySegment parses one dotted-key segment at s[i:]: a basic string with
// escapes, a literal string, or a bare key (A-Za-z0-9_-). It returns the
// segment's value and the index after it.
func parseKeySegment(s string, i int) (seg string, next int, ok bool) {
	if i >= len(s) {
		return "", i, false
	}
	switch s[i] {
	case '"':
		var b strings.Builder
		i++
		for i < len(s) {
			c := s[i]
			switch c {
			case '"':
				return b.String(), i + 1, true
			case '\\':
				r, n, escOK := parseTOMLEscape(s[i:])
				if !escOK {
					return "", i, false
				}
				b.WriteString(r)
				i += n
			default:
				b.WriteByte(c)
				i++
			}
		}
		return "", i, false
	case '\'':
		end := strings.IndexByte(s[i+1:], '\'')
		if end < 0 {
			return "", i, false
		}
		return s[i+1 : i+1+end], i + 2 + end, true
	default:
		start := i
		for i < len(s) && isBareKeyChar(s[i]) {
			i++
		}
		if i == start {
			return "", i, false
		}
		return s[start:i], i, true
	}
}

func isBareKeyChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-'
}

// parseTOMLEscape decodes the escape sequence at the start of s (which begins
// with a backslash) and returns the decoded text and the sequence length.
func parseTOMLEscape(s string) (string, int, bool) {
	if len(s) < 2 {
		return "", 0, false
	}
	switch s[1] {
	case 'b':
		return "\b", 2, true
	case 't':
		return "\t", 2, true
	case 'n':
		return "\n", 2, true
	case 'f':
		return "\f", 2, true
	case 'r':
		return "\r", 2, true
	case '"':
		return `"`, 2, true
	case '\\':
		return `\`, 2, true
	case 'u', 'U':
		width := 4
		if s[1] == 'U' {
			width = 8
		}
		if len(s) < 2+width {
			return "", 0, false
		}
		var r rune
		for _, h := range s[2 : 2+width] {
			var v rune
			switch {
			case h >= '0' && h <= '9':
				v = h - '0'
			case h >= 'a' && h <= 'f':
				v = h - 'a' + 10
			case h >= 'A' && h <= 'F':
				v = h - 'A' + 10
			default:
				return "", 0, false
			}
			r = r<<4 | v
		}
		if !utf8.ValidRune(r) {
			return "", 0, false
		}
		return string(r), 2 + width, true
	}
	return "", 0, false
}
