package validate

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// RDAYBLUEX-008: old-key absence is conservative — any DS with the old key's
// tag and algorithm, whatever its digest type or value, keeps the key
// "present"; new-key presence still requires an exact supported digest.

func withDigest(k *dns.DNSKEY, digestType uint8, digest string) *dns.DS {
	ds := &dns.DS{Hdr: dns.RR_Header{Name: "child.parent.test.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 3600},
		KeyTag: k.KeyTag(), Algorithm: k.Algorithm, DigestType: digestType, Digest: digest}
	return ds
}

func TestRDAYBLUEX008_AbsenceRequiresNoTagAlgorithmMatchAnywhere(t *testing.T) {
	lab := newParentLab(t)
	v := lab.validator()
	oldK := testKSK(t, 1)
	otherK := testKSK(t, 2)
	sha256 := oldK.ToDS(dns.SHA256)

	cases := []struct {
		name string
		ds   *dns.DS
	}{
		{"SHA-1 digest for the old key", withDigest(oldK, dns.SHA1, strings.Repeat("ab", 20))},
		{"unknown digest type for the old key", withDigest(oldK, 200, strings.Repeat("cd", 32))},
		{"wrong SHA-256 digest with the old tag and algorithm", withDigest(oldK, dns.SHA256, strings.Repeat("ef", 32))},
		{"another key's DS colliding on tag and algorithm", withDigest(oldK, dns.SHA256, strings.ToUpper(otherK.ToDS(dns.SHA256).Digest))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Only one parent server still holds the residual record.
			lab.set(lab.v4(), c.ds)
			lab.set(lab.v6())
			obs, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{oldK})
			if err != nil {
				t.Fatal(err)
			}
			if obs.AbsentOnAll[oldK.KeyTag()] {
				t.Fatalf("%s must keep the old key present (AbsentOnAll=false): %+v", c.name, obs)
			}
			if obs.PresentOnAll[oldK.KeyTag()] {
				t.Fatalf("%s is not an exact supported digest on every server: %+v", c.name, obs)
			}
		})
	}

	// An unrelated tag/algorithm does not block absence.
	unrelated := otherK.ToDS(dns.SHA256)
	if unrelated.KeyTag == oldK.KeyTag() {
		t.Skip("key tag collision in generated test keys")
	}
	lab.set(lab.v4(), unrelated)
	lab.set(lab.v6(), unrelated)
	obs, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{oldK})
	if err != nil {
		t.Fatal(err)
	}
	if !obs.AbsentOnAll[oldK.KeyTag()] {
		t.Fatalf("an unrelated DS must not block absence: %+v", obs)
	}

	// Exact SHA-256 or SHA-384 establishes presence for a new key.
	lab.set(lab.v4(), sha256)
	lab.set(lab.v6(), sha256)
	obs, err = v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{oldK})
	if err != nil || !obs.PresentOnAll[oldK.KeyTag()] || obs.AbsentOnAll[oldK.KeyTag()] {
		t.Fatalf("exact SHA-256 on every server is presence (err %v): %+v", err, obs)
	}
	sha384 := oldK.ToDS(dns.SHA384)
	lab.set(lab.v4(), sha384)
	lab.set(lab.v6(), sha384)
	obs, err = v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{oldK})
	if err != nil || !obs.PresentOnAll[oldK.KeyTag()] {
		t.Fatalf("exact SHA-384 on every server is presence (err %v): %+v", err, obs)
	}
	// SHA-256 on one server and SHA-1 on the other: not present on all, and
	// not absent anywhere.
	lab.set(lab.v6(), withDigest(oldK, dns.SHA1, strings.Repeat("ab", 20)))
	obs, err = v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{oldK})
	if err != nil || obs.PresentOnAll[oldK.KeyTag()] || obs.AbsentOnAll[oldK.KeyTag()] {
		t.Fatalf("mixed digests: neither present-on-all nor absent (err %v): %+v", err, obs)
	}
}
