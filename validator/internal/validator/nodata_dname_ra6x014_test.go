package validator

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// RA6X-014 (Medium): valid wildcard NODATA, empty-non-terminal NODATA and
// DNAME answers must be accepted, while unsigned ordinary CNAMEs, false
// NXDOMAIN for existing non-terminals and positive answers keep their strict
// handling.

func TestRA6X014_WildcardNODATA(t *testing.T) {
	const zone = "example.com."
	apexTypes := []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY}

	t.Run("NSEC", func(t *testing.T) {
		f := newLeafFixture(t, zone)
		// Zone: apex, *.example.com. (A only), mail.example.com. — the query
		// foo.example.com. AAAA has no exact match; the wildcard exists but has
		// no AAAA. The apex NSEC covers foo (between example.com. and mail...).
		// Canonical order: example.com. < *.example.com. < foo... < mail...
		apex := nsecRR(zone, "*.example.com.", apexTypes...)
		wild := nsecRR("*.example.com.", "mail.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC)
		rv := f.queryLeaf(t, "foo.example.com.", dns.TypeAAAA, dns.RcodeSuccess, nil, f.zone.signedAuthority(t, apex, wild))
		if rv.DenialProof == nil || !rv.DenialProof.Verified {
			t.Fatalf("wildcard NODATA under NSEC must verify: %+v", rv)
		}
		if rv.DenialProof.ClosestEncloser != zone {
			t.Fatalf("closest encloser = %q, want %q", rv.DenialProof.ClosestEncloser, zone)
		}
		if verdict, _ := recordValidationVerdict(rv); verdict != StatusSecure {
			t.Fatalf("verdict = %s, want secure", verdict)
		}
		// The wildcard HAS the type: not NODATA.
		wildWithAAAA := nsecRR("*.example.com.", "mail.example.com.", dns.TypeA, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC)
		rv = f.queryLeaf(t, "foo.example.com.", dns.TypeAAAA, dns.RcodeSuccess, nil, f.zone.signedAuthority(t, apex, wildWithAAAA))
		if rv.DenialProof == nil || rv.DenialProof.Verified {
			t.Fatalf("wildcard that has the type must not prove NODATA: %+v", rv)
		}
	})

	t.Run("NSEC3", func(t *testing.T) {
		f := newLeafFixture(t, zone)
		p := nsec3Params{salt: "ABCD", iter: 1}
		// Closest encloser (apex) matches; next closer (foo) is covered by the
		// apex's interval or the wildcard's; the wildcard NSEC3 lacks AAAA.
		hApex, hWild := p.hashOf(t, zone), p.hashOf(t, "*.example.com.")
		lowest, highest := strings.Repeat("0", 32), strings.Repeat("V", 32)
		recs := []dns.RR{
			p.nsec3RRHashed(t, zone, lowest, hApex, 0, dns.TypeA),
			p.nsec3RRHashed(t, zone, hApex, bumpHash(hApex), 0, dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeDNSKEY),
			p.nsec3RRHashed(t, zone, bumpHash(hApex), highest, 0, dns.TypeA),
			p.nsec3RRHashed(t, zone, hWild, bumpHash(hWild), 0, dns.TypeA, dns.TypeRRSIG),
		}
		rv := f.queryLeaf(t, "foo.example.com.", dns.TypeAAAA, dns.RcodeSuccess, nil, f.zone.signedAuthority(t, recs...))
		if rv.DenialProof == nil || !rv.DenialProof.Verified {
			t.Fatalf("wildcard NODATA under NSEC3 must verify: %+v", rv)
		}
		if rv.DenialProof.ClosestEncloser != zone || rv.DenialProof.NextCloser != "foo.example.com." {
			t.Fatalf("proof names = %+v", rv.DenialProof)
		}
		if verdict, _ := recordValidationVerdict(rv); verdict != StatusSecure {
			t.Fatalf("verdict = %s, want secure", verdict)
		}
		// Without the wildcard record it is not proven.
		rv = f.queryLeaf(t, "foo.example.com.", dns.TypeAAAA, dns.RcodeSuccess, nil, f.zone.signedAuthority(t, recs[:3]...))
		if rv.DenialProof == nil || rv.DenialProof.Verified {
			t.Fatalf("wildcard NODATA without the wildcard NSEC3 must not verify: %+v", rv)
		}
	})
}

func TestRA6X014_EmptyNonTerminalNODATA(t *testing.T) {
	const zone = "example.com."
	f := newLeafFixture(t, zone)
	apexTypes := []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeDNSKEY}
	// a.example.com. is an empty non-terminal: only x.a.example.com. has data.
	apex := nsecRR(zone, "x.a.example.com.", apexTypes...)
	rv := f.queryLeaf(t, "a.example.com.", dns.TypeA, dns.RcodeSuccess, nil, f.zone.signedAuthority(t, apex))
	if rv.DenialProof == nil || !rv.DenialProof.Verified {
		t.Fatalf("NODATA for an empty non-terminal must verify: %+v", rv)
	}
	if verdict, _ := recordValidationVerdict(rv); verdict != StatusSecure {
		t.Fatalf("verdict = %s, want secure", verdict)
	}
	// The same record still refutes NXDOMAIN for that name (RA6X-010).
	rv = f.queryLeaf(t, "a.example.com.", dns.TypeA, dns.RcodeNameError, nil, f.zone.signedAuthority(t, apex))
	if rv.DenialProof == nil || rv.DenialProof.Verified {
		t.Fatalf("NXDOMAIN for an existing non-terminal must stay rejected: %+v", rv)
	}
}

func TestRA6X014_DNAME(t *testing.T) {
	const zone = "example.com."
	f := newLeafFixture(t, zone)

	dname := &dns.DNAME{Hdr: rrHdr("old.example.com.", dns.TypeDNAME), Target: "new.example.com."}
	dnameSig := f.zone.signZSK(t, dname)
	synth := &dns.CNAME{Hdr: rrHdr("www.old.example.com.", dns.TypeCNAME), Target: "www.new.example.com."}
	// A target A record signed in-zone, as a same-zone DNAME response carries.
	targetA := &dns.A{Hdr: rrHdr("www.new.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.5")}
	targetSig := f.zone.signZSK(t, targetA)

	// Genuine signed DNAME answer.
	rv := f.queryLeaf(t, "www.old.example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{dname, dnameSig, synth, targetA, targetSig}, nil)
	if !rv.RRSIGVerified || rv.RecordType != "DNAME" {
		t.Fatalf("signed DNAME answer must verify: %+v", rv)
	}
	if rv.SynthesizedFrom != "old.example.com." || rv.Target != "www.new.example.com." {
		t.Fatalf("DNAME metadata = from %q target %q", rv.SynthesizedFrom, rv.Target)
	}
	if verdict, _ := recordValidationVerdict(rv); verdict != StatusSecure {
		t.Fatalf("verdict = %s, want secure", verdict)
	}

	// Tampered synthesized target.
	bad := &dns.CNAME{Hdr: rrHdr("www.old.example.com.", dns.TypeCNAME), Target: "attacker.invalid."}
	rv = f.queryLeaf(t, "www.old.example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{dname, dnameSig, bad}, nil)
	if rv.RRSIGVerified || !strings.Contains(rv.Error, "does not match the DNAME substitution") {
		t.Fatalf("tampered synthesized CNAME must be rejected: %+v", rv)
	}

	// Unsigned DNAME.
	rv = f.queryLeaf(t, "www.old.example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{dname, synth}, nil)
	if rv.RRSIGVerified || !strings.Contains(rv.Error, "DNAME RRSIG verification failed") {
		t.Fatalf("unsigned DNAME must be rejected: %+v", rv)
	}

	// An ordinary unsigned CNAME (no DNAME) is still rejected.
	plain := &dns.CNAME{Hdr: rrHdr("alias.example.com.", dns.TypeCNAME), Target: "www.example.com."}
	rv = f.queryLeaf(t, "alias.example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{plain}, nil)
	if rv.RRSIGVerified || rv.RecordType != "CNAME" {
		t.Fatalf("unsigned ordinary CNAME must be rejected: %+v", rv)
	}

	// Substitution exceeding the name-length limit: the server answers
	// YXDOMAIN with the (signed) DNAME and no CNAME (RFC 6672 §2.2). The
	// redirection is authenticated but the name cannot be resolved: never
	// secure, reported as indeterminate rather than as a forgery.
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".new.example.com."
	dnameLong := &dns.DNAME{Hdr: rrHdr("old.example.com.", dns.TypeDNAME), Target: long}
	dnameLongSig := f.zone.signZSK(t, dnameLong)
	longQ := strings.Repeat("d", 63) + ".old.example.com."
	rv = f.queryLeaf(t, longQ, dns.TypeA, dns.RcodeYXDomain, []dns.RR{dnameLong, dnameLongSig}, nil)
	if rv.RRSIGVerified || !strings.Contains(rv.Error, "name length limit") {
		t.Fatalf("over-long DNAME substitution must be rejected: %+v", rv)
	}
	if verdict, _ := recordValidationVerdict(rv); verdict == StatusSecure {
		t.Fatal("YXDOMAIN DNAME answer must not be secure")
	}
	// YXDOMAIN with an unsigned DNAME is bogus, not indeterminate.
	rv = f.queryLeaf(t, longQ, dns.TypeA, dns.RcodeYXDomain, []dns.RR{dnameLong}, nil)
	if verdict, _ := recordValidationVerdict(rv); verdict != StatusBogus {
		t.Fatalf("unsigned DNAME behind YXDOMAIN must be bogus, got %s (%s)", verdict, rv.Error)
	}

	// Helper-level substitution checks.
	if got, err := substituteDNAME("www.old.example.com.", "old.example.com.", "new.example.com."); err != nil || got != "www.new.example.com." {
		t.Fatalf("substituteDNAME = %q, %v", got, err)
	}
	if got, err := substituteDNAME("a.b.old.example.com.", "old.example.com.", "."); err != nil || got != "a.b." {
		t.Fatalf("substituteDNAME to root = %q, %v", got, err)
	}
	if _, err := substituteDNAME("old.example.com.", "old.example.com.", "new.example.com."); err == nil {
		t.Fatal("DNAME owner itself is not redirected (RFC 6672 §2.2)")
	}
}
