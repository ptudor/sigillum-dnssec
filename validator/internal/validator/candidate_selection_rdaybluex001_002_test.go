package validator

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// RDAYBLUEX-001: parent-DS candidate selection is authentication-aware. A
// faulty, unsigned or hostile first parent response can never block a later
// authentic one; every bad responder stays visible as a disagreement; quick
// mode stops only after an authentic result; all-invalid stays non-Secure.
//
// RDAYBLUEX-002: leaf candidate selection fully authenticates the path each
// candidate represents (positive RRset, ordinary CNAME, DNAME + synthesized
// CNAME, NSEC/NSEC3 denial); an invalid earlier candidate never outranks a
// later valid one; cancellation ends the query loop; alias discovery
// continues past servers that serve no alias.

// The parent's servers are queried in address order: 127.0.0.1 ("v4")
// first, ::1 ("v6") second (A before AAAA in the infrastructure answers).

// attackerSignedDS returns the child's DS signed by a key the parent does not hold.
func attackerSignedDS(t *testing.T, f *dualServerFixture) []dns.RR {
	t.Helper()
	rogue := newTestZone(t, "test.")
	ds := f.child.ds(t)
	return []dns.RR{ds, rogue.signZSK(t, ds)}
}

func TestRDAYBLUEX001_LaterAuthenticDSWinsOverBadFirstResponse(t *testing.T) {
	cases := []struct {
		name  string
		first func(req *dns.Msg) *dns.Msg
		want  string // substring expected in the disagreement
	}{
		{"unsigned DS first", func(req *dns.Msg) *dns.Msg {
			resp := new(dns.Msg)
			resp.Answer = []dns.RR{nil}
			return resp
		}, "RRSIG"},
		{"attacker-signed DS first", nil, "RRSIG"},
		{"unsigned NXDOMAIN first", func(req *dns.Msg) *dns.Msg {
			resp := new(dns.Msg)
			resp.Rcode = dns.RcodeNameError
			return resp
		}, "error"},
		{"unsigned NODATA first", func(req *dns.Msg) *dns.Msg {
			return new(dns.Msg)
		}, "different DS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newDualServerFixture(t)
			first := c.first
			switch c.name {
			case "unsigned DS first":
				ds := f.child.ds(t)
				first = func(req *dns.Msg) *dns.Msg {
					resp := new(dns.Msg)
					resp.Answer = []dns.RR{ds}
					return resp
				}
			case "attacker-signed DS first":
				rrs := attackerSignedDS(t, f)
				first = func(req *dns.Msg) *dns.Msg {
					resp := new(dns.Msg)
					resp.Answer = rrs
					return resp
				}
			}
			f.m.onFamily("v4", f.child.name, dns.TypeDS, first)
			zr := f.validate(t)
			if zr.Status != StatusSecure {
				t.Fatalf("the later authentic DS must be selected; got %s (%v)", zr.Status, zr.Errors)
			}
			var parentDis []Disagreement
			for _, d := range zr.Disagreements {
				if strings.HasPrefix(d.Server, "parent ") {
					parentDis = append(parentDis, d)
				}
			}
			if len(parentDis) != 1 || parentDis[0].IP != "127.0.0.1" || !strings.Contains(parentDis[0].Issue+parentDis[0].Got, c.want) {
				t.Fatalf("the bad first responder must remain visible as a diagnostic (%q), got %+v", c.want, zr.Disagreements)
			}
		})
	}
}

func TestRDAYBLUEX001_AuthenticatedDenialWinsOverInvalidDenial(t *testing.T) {
	f := newDualServerFixture(t)
	// An unsigned child: no DNSKEY served (the mock answers empty NOERROR).
	f.m.on(f.child.name, dns.TypeDNSKEY, func(req *dns.Msg) *dns.Msg { return new(dns.Msg) })
	deleg := nsecRR(f.child.name, "zzz.test.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)
	// v4: the delegation NSEC without its signature; v6: signed.
	f.m.onFamily("v4", f.child.name, dns.TypeDS, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Ns = []dns.RR{deleg}
		return resp
	})
	f.m.onFamily("v6", f.child.name, dns.TypeDS, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Ns = f.parent.signedAuthority(t, deleg)
		return resp
	})
	zr := f.validate(t)
	if zr.Status != StatusInsecure {
		t.Fatalf("the authenticated denial must be selected: got %s (%v)", zr.Status, zr.Errors)
	}
	if zr.DenialProof == nil || !zr.DenialProof.Verified {
		t.Fatalf("the selected candidate's absence proof must be recorded: %+v", zr.DenialProof)
	}
	found := false
	for _, d := range zr.Disagreements {
		if strings.HasPrefix(d.Server, "parent ") && d.IP == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the invalid denial responder must be a diagnostic, got %+v", zr.Disagreements)
	}

	// Unsigned NXDOMAIN first, authenticated denial second.
	f.m.onFamily("v4", f.child.name, dns.TypeDS, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Rcode = dns.RcodeNameError
		return resp
	})
	if zr := f.validate(t); zr.Status != StatusInsecure {
		t.Fatalf("an unauthenticated NXDOMAIN must not decide; got %s (%v)", zr.Status, zr.Errors)
	}
}

func TestRDAYBLUEX001_AllInvalidStaysNonSecure(t *testing.T) {
	f := newDualServerFixture(t)
	ds := f.child.ds(t)
	unsigned := func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{ds}
		return resp
	}
	f.m.onFamily("v4", f.child.name, dns.TypeDS, unsigned)
	f.m.onFamily("v6", f.child.name, dns.TypeDS, unsigned)
	zr := f.validate(t)
	if zr.Status == StatusSecure || zr.Status == StatusInsecure {
		t.Fatalf("no authentic candidate: the result must not be Secure or Insecure, got %s", zr.Status)
	}
	if zr.DSValidation == nil || zr.DSValidation.RRSIGVerified {
		t.Fatalf("the failed validation must be reported for the verdict machinery: %+v", zr.DSValidation)
	}

	// Unsigned NXDOMAIN on both: neither Secure nor Insecure either.
	nx := func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Rcode = dns.RcodeNameError
		return resp
	}
	f.m.onFamily("v4", f.child.name, dns.TypeDS, nx)
	f.m.onFamily("v6", f.child.name, dns.TypeDS, nx)
	f.m.on(f.child.name, dns.TypeDNSKEY, func(req *dns.Msg) *dns.Msg { return new(dns.Msg) })
	if zr := f.validate(t); zr.Status == StatusSecure || zr.Status == StatusInsecure {
		t.Fatalf("unauthenticated NXDOMAIN everywhere must not be authoritative absence, got %s", zr.Status)
	}
}

// Quick mode: "first" means the first response that authenticates.
func TestRDAYBLUEX001_QuickModeStopsOnlyAfterAuthentication(t *testing.T) {
	f := newDualServerFixture(t)
	ds := f.child.ds(t)
	f.m.onFamily("v4", f.child.name, dns.TypeDS, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{ds}
		return resp
	})
	v := f.m.newValidator()
	v.SetQuickMode(true)
	zr, err := v.validateZone(testCtx(t), "child.test.", []string{".", "test.", "child.test."}, f.parent.keyRecords(), false)
	if err != nil {
		t.Fatal(err)
	}
	if zr.Status != StatusSecure {
		t.Fatalf("quick mode must continue past an unauthenticated first answer, got %s (%v)", zr.Status, zr.Errors)
	}
	// Once authenticated, quick mode stops: the second parent server is
	// queried at most once for DS (the authentic one), never a third time.
	dsQueries := 0
	for _, q := range f.m.questions() {
		if q.Qtype == dns.TypeDS && dns.CanonicalName(q.Name) == f.child.name {
			dsQueries++
		}
	}
	if dsQueries != 2 {
		t.Fatalf("quick mode queries until the first authentic answer and then stops; got %d DS queries", dsQueries)
	}
}

// --- RDAYBLUEX-002 ----------------------------------------------------------

func leafA(name, ip string) *dns.A {
	return &dns.A{Hdr: rrHdr(name, dns.TypeA), A: net.ParseIP(ip)}
}

func TestRDAYBLUEX002_InvalidDenialThenValidPositive(t *testing.T) {
	f := newDualServerFixture(t)
	v := f.m.newValidator()
	a := leafA("www.child.test.", "192.0.2.1")
	f.m.answer("www.child.test.", dns.TypeA, a, f.child.signZSK(t, a))
	// v4: NXDOMAIN with an unsigned NSEC (an invalid denial).
	f.m.onFamily("v4", "www.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Rcode = dns.RcodeNameError
		resp.Ns = []dns.RR{nsecRR("child.test.", "zzz.child.test.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)}
		return resp
	})
	rv := v.verifyActualRecord(testCtx(t), "www.child.test.", "child.test.", f.child.keyRecords())
	if !rv.RRSIGVerified || rv.DenialProof != nil {
		t.Fatalf("the later valid positive answer must be selected over an invalid denial: %+v", rv)
	}
	if len(rv.ServerDisagreements) != 1 || !strings.Contains(rv.ServerDisagreements[0], "127.0.0.1") {
		t.Fatalf("the invalid responder must be reported: %+v", rv.ServerDisagreements)
	}

	// The reverse: a valid (signed) NXDOMAIN denial first, an unsigned
	// positive second — the authenticated denial is the selected path.
	f.m.clearFamilyOverrides()
	nsec := nsecRR("child.test.", "zzz.child.test.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)
	f.m.onFamily("v4", "www.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Rcode = dns.RcodeNameError
		resp.Ns = f.child.signedAuthority(t, nsec)
		return resp
	})
	f.m.onFamily("v6", "www.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{a}
		return resp
	})
	rv = v.verifyActualRecord(testCtx(t), "www.child.test.", "child.test.", f.child.keyRecords())
	if rv.DenialProof == nil || !rv.DenialProof.Verified {
		t.Fatalf("an authenticated denial must outrank an unsigned positive answer: %+v", rv)
	}
}

func TestRDAYBLUEX002_InvalidDNAMEThenValidPositive(t *testing.T) {
	f := newDualServerFixture(t)
	v := f.m.newValidator()
	qname := "www.sub.child.test."
	a := leafA(qname, "192.0.2.7")
	f.m.answer(qname, dns.TypeA, a, f.child.signZSK(t, a))
	// v4: an UNSIGNED DNAME redirection with its synthesized CNAME.
	f.m.onFamily("v4", qname, dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{
			&dns.DNAME{Hdr: rrHdr("sub.child.test.", dns.TypeDNAME), Target: "other.test."},
			&dns.CNAME{Hdr: rrHdr(qname, dns.TypeCNAME), Target: "www.other.test."},
		}
		return resp
	})
	rv := v.verifyActualRecord(testCtx(t), qname, "child.test.", f.child.keyRecords())
	if !rv.RRSIGVerified || rv.RecordType != "A" {
		t.Fatalf("the valid positive answer must be selected over an unverified DNAME path: %+v", rv)
	}
	if len(rv.ServerDisagreements) != 1 {
		t.Fatalf("the invalid DNAME responder must be reported: %+v", rv.ServerDisagreements)
	}

	// A properly signed DNAME path is itself a valid candidate: with the
	// signed DNAME first and an unsigned A second, the DNAME path is chosen.
	f.m.clearFamilyOverrides()
	dname := &dns.DNAME{Hdr: rrHdr("sub.child.test.", dns.TypeDNAME), Target: "other.test."}
	f.m.onFamily("v4", qname, dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{dname, f.child.signZSK(t, dname), &dns.CNAME{Hdr: rrHdr(qname, dns.TypeCNAME), Target: "www.other.test."}}
		return resp
	})
	f.m.onFamily("v6", qname, dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{a}
		return resp
	})
	rv = v.verifyActualRecord(testCtx(t), qname, "child.test.", f.child.keyRecords())
	if !rv.RRSIGVerified || rv.RecordType != "DNAME" || rv.Target != "www.other.test." {
		t.Fatalf("an authenticated DNAME path must be selected over an unsigned positive answer: %+v", rv)
	}
}

func TestRDAYBLUEX002_InvalidCNAMEThenValidCNAME(t *testing.T) {
	f := newDualServerFixture(t)
	v := f.m.newValidator()
	cname := &dns.CNAME{Hdr: rrHdr("alias.child.test.", dns.TypeCNAME), Target: "www.child.test."}
	f.m.answer("alias.child.test.", dns.TypeA, cname, f.child.signZSK(t, cname))
	f.m.onFamily("v4", "alias.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{cname} // unsigned
		return resp
	})
	rv := v.verifyActualRecord(testCtx(t), "alias.child.test.", "child.test.", f.child.keyRecords())
	if !rv.RRSIGVerified || rv.RecordType != "CNAME" || rv.Target != "www.child.test." {
		t.Fatalf("the valid CNAME must be selected: %+v", rv)
	}
	if len(rv.ServerDisagreements) != 1 || !strings.Contains(rv.ServerDisagreements[0], "does not verify") {
		t.Fatalf("the unsigned responder must be reported: %+v", rv.ServerDisagreements)
	}
}

func TestRDAYBLUEX002_AliasDiscoveryContinuesPastNoAlias(t *testing.T) {
	f := newDualServerFixture(t)
	v := f.m.newValidator()
	a := leafA("www.child.test.", "192.0.2.1")
	// v4 answers the name directly (no alias); v6 serves the alias.
	f.m.onFamily("v4", "www.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{a}
		return resp
	})
	f.m.onFamily("v6", "www.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{&dns.CNAME{Hdr: rrHdr("www.child.test.", dns.TypeCNAME), Target: "target.child.test."}}
		return resp
	})
	if got := v.discoverAliasTarget(testCtx(t), "www.child.test.", "child.test."); got != "target.child.test." {
		t.Fatalf("alias discovery must continue past a server that serves no alias, got %q", got)
	}
	// A structurally invalid target is never accepted.
	f.m.onFamily("v6", "www.child.test.", dns.TypeA, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.Answer = []dns.RR{&dns.CNAME{Hdr: rrHdr("www.child.test.", dns.TypeCNAME), Target: "bad name.test."}}
		return resp
	})
	if got := v.discoverAliasTarget(testCtx(t), "www.child.test.", "child.test."); got != "" {
		t.Fatalf("a malformed alias target must be rejected, got %q", got)
	}
}

// No leaf query starts once cancellation has been observed.
func TestRDAYBLUEX002_CancellationStopsQueries(t *testing.T) {
	f := newDualServerFixture(t)
	v := f.m.newValidator()
	a := leafA("www.child.test.", "192.0.2.1")
	f.m.answer("www.child.test.", dns.TypeA, a, f.child.signZSK(t, a))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := len(f.m.questions())
	addrs := []string{net.JoinHostPort("127.0.0.1", f.m.port), net.JoinHostPort("::1", f.m.port)}
	qr, _ := v.queryLeafAllServers(ctx, addrs, "www.child.test.", "child.test.", f.child.keyRecords())
	if qr != nil {
		t.Fatal("a cancelled validation must not select a candidate")
	}
	for _, q := range f.m.questions()[before:] {
		if dns.CanonicalName(q.Name) == "www.child.test." {
			t.Fatalf("a leaf query was issued after cancellation: %+v", q)
		}
	}
	_ = dnspkg.SectionAnswer
}
