package signer

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// RM51X-003: only a leftmost label that is exactly "*" is a wildcard
// (RFC 4592 §2.1.1). miekg/dns decides the RRSIG Labels count from the
// presentation prefix, so owners such as "*foo" and "**" were signed as
// wildcard expansions (Labels one short), the self-check passed because
// Verify reconstructs the owner the same way, and real validators demanded a
// closest-encloser proof the server never sends.

func TestRM51X003_CanonicalNameEscapesNonWildcardAsterisk(t *testing.T) {
	cases := map[string]string{
		"**.example.com.":       `\*\*.example.com.`,
		"*foo.example.com.":     `\*foo.example.com.`,
		"*-x.example.com.":      `\*-x.example.com.`,
		`\042\042.example.com.`: `\*\*.example.com.`,
		"*.example.com.":        "*.example.com.",
		`\*.example.com.`:       "*.example.com.",
		`\042.example.com.`:     "*.example.com.",
		"a.*.example.com.":      "a.*.example.com.",
		"*.*.example.com.":      "*.*.example.com.",
		`\*\*.example.com.`:     `\*\*.example.com.`, // idempotent
	}
	for in, want := range cases {
		got := canonicalName(in)
		if got != want {
			t.Errorf("canonicalName(%q) = %q, want %q", in, got, want)
		}
		if wireKey(t, got) != wireKey(t, in) {
			t.Errorf("canonicalName(%q) = %q changed the wire name", in, got)
		}
	}
}

func TestRM51X003_RRSIGLabels(t *testing.T) {
	cases := map[string]uint8{
		".":                 0,
		"example.com.":      2,
		"*.example.com.":    2,
		`\*.example.com.`:   2,
		"*.*.example.com.":  3,
		"**.example.com.":   3,
		"*foo.example.com.": 3,
		"*-x.example.com.":  3,
		"a.*.example.com.":  4,
		"WWW.Example.COM.":  3,
		`a\.b.example.com.`: 3,
	}
	for name, want := range cases {
		if got := rrsigLabels(name); got != want {
			t.Errorf("rrsigLabels(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestRM51X003_OrdinaryAsteriskOwnersKeepFullLabelCount(t *testing.T) {
	for _, mode := range []string{"nsec", "nsec3"} {
		t.Run(mode, func(t *testing.T) {
			z := newSemZone(t, mode, baseZone+`*	IN	TXT	"wildcard"
*foo	IN	TXT	"ordinary label"
**	IN	TXT	"ordinary label"
*-x	IN	TXT	"ordinary label"
a.*	IN	TXT	"asterisk label below a"
`)
			if err := z.signer.SignZone(z.domain); err != nil {
				t.Fatalf("SignZone: %v", err)
			}
			records := parseSigned(t, z.outputPath(), z.domain)
			independentVerify(t, records, nil)

			want := map[string]uint8{
				wireKey(t, "*.example.com."):    2,
				wireKey(t, "*foo.example.com."): 3,
				wireKey(t, "**.example.com."):   3,
				wireKey(t, "*-x.example.com."):  3,
				wireKey(t, "a.*.example.com."):  4,
			}
			seen := map[string]int{}
			for _, rr := range records {
				sig, ok := rr.(*dns.RRSIG)
				if !ok {
					continue
				}
				key := wireKey(t, sig.Hdr.Name)
				w, ok := want[key]
				if !ok {
					continue
				}
				seen[key]++
				if sig.Labels != w {
					t.Fatalf("RRSIG %s %s Labels = %d, want %d", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered], sig.Labels, w)
				}
				// The written spelling must round-trip through the zone parser
				// to the same wire owner as the record it covers.
				if dns.CountLabel(sig.Hdr.Name) != int(w)+map[bool]int{true: 1, false: 0}[strings.HasPrefix(canonicalName(sig.Hdr.Name), "*.")] {
					t.Fatalf("RRSIG owner %q parsed to %d labels", sig.Hdr.Name, dns.CountLabel(sig.Hdr.Name))
				}
			}
			for key, n := range seen {
				if n < 1 {
					t.Fatalf("no RRSIG at %q", key)
				}
			}
			if len(seen) != len(want) {
				t.Fatalf("RRSIGs found for %d of %d owners", len(seen), len(want))
			}
		})
	}
}

func TestRM51X003_VerifierRejectsWildcardLabelsOnOrdinaryOwner(t *testing.T) {
	z := newSemZone(t, "nsec", baseZone+"**\tIN\tTXT\t\"ordinary label\"\n")
	z.signer.mutateBeforeVerify = func(records []dns.RR) []dns.RR {
		for _, rr := range records {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeTXT && wireKey(t, sig.Hdr.Name) == wireKey(t, "**.example.com.") {
				sig.Labels--
			}
		}
		return records
	}
	err := z.signer.SignZone(z.domain)
	if err == nil || !strings.Contains(err.Error(), "post-sign verification failed") || !strings.Contains(err.Error(), "Labels=2, want 3") {
		t.Fatalf("a wildcard label count on an ordinary owner must not publish, got %v", err)
	}
}
