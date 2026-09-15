package validate

import (
	"crypto"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// signedChildZone builds a DNSKEY RRset signed by its KSK and an SOA signed
// by its ZSK for child.parent.test., valid over [inception, expiration].
func signedChildZone(t *testing.T, inception, expiration time.Time) (ksk, zsk *dns.DNSKEY, rrs []dns.RR) {
	t.Helper()
	const zone = "child.parent.test."
	mk := func(flags uint16) (*dns.DNSKEY, crypto.Signer) {
		k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600}, Flags: flags, Protocol: 3, Algorithm: dns.ED25519}
		priv, err := k.Generate(256)
		if err != nil {
			t.Fatal(err)
		}
		return k, priv.(crypto.Signer)
	}
	ksk, kskPriv := mk(257)
	zsk, zskPriv := mk(256)
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns4.lab.", Mbox: "h." + zone, Serial: 1, Refresh: 1, Retry: 1, Expire: 1, Minttl: 1}
	sign := func(rrset []dns.RR, key *dns.DNSKEY, signer crypto.Signer) *dns.RRSIG {
		hdr := rrset[0].Header()
		sig := &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: hdr.Ttl},
			TypeCovered: hdr.Rrtype, Algorithm: key.Algorithm, Labels: 3, OrigTtl: hdr.Ttl,
			Expiration: uint32(expiration.Unix()), Inception: uint32(inception.Unix()),
			KeyTag: key.KeyTag(), SignerName: zone,
		}
		if err := sig.Sign(signer, rrset); err != nil {
			t.Fatal(err)
		}
		return sig
	}
	rrs = []dns.RR{ksk, zsk, sign([]dns.RR{ksk, zsk}, ksk, kskPriv), soa, sign([]dns.RR{soa}, zsk, zskPriv)}
	return ksk, zsk, rrs
}

// ProbeServedKeys reports the served DNSKEY RRset and its signers from every
// authoritative server, tolerates a server that does not answer, and fails
// only when none does.
func TestProbeServedKeys(t *testing.T) {
	lab := newParentLab(t)
	v := lab.validator()
	now := time.Now()
	ksk, zsk, rrs := signedChildZone(t, now.Add(-time.Hour), now.Add(time.Hour))
	lab.serve(lab.v4(), rrs...)
	lab.serve(lab.v6(), rrs...)

	served, err := v.ProbeServedKeys("child.parent.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(served.Servers) != 2 || len(served.Unreachable) != 0 {
		t.Fatalf("both servers must answer: %+v", served)
	}
	if len(served.DNSKEYs) != 2 || !served.Published(ksk) || !served.Published(zsk) || served.DNSKEYTTL != 3600 {
		t.Fatalf("served DNSKEY RRset described wrongly: %+v", served)
	}
	if fmt.Sprint(served.SOASigners) != fmt.Sprint([]uint16{zsk.KeyTag()}) || fmt.Sprint(served.DNSKEYSigners) != fmt.Sprint([]uint16{ksk.KeyTag()}) {
		t.Fatalf("signers: SOA %v DNSKEY %v", served.SOASigners, served.DNSKEYSigners)
	}
	if served.StaleSignatures {
		t.Fatal("in-window signatures are not stale")
	}

	_, _, stale := signedChildZone(t, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	lab.serve(lab.v4(), stale...)
	lab.serve(lab.v6(), stale...)
	served, err = v.ProbeServedKeys("child.parent.test.")
	if err != nil || !served.StaleSignatures || len(served.SOASigners) != 1 {
		t.Fatalf("expired signatures must be reported as stale but still attributed: %+v, %v", served, err)
	}

	lab.servers[1].Shutdown()
	v.timeout = 300 * time.Millisecond
	served, err = v.ProbeServedKeys("child.parent.test.")
	if err != nil || len(served.Servers) != 1 || len(served.Unreachable) != 1 {
		t.Fatalf("one silent server is reported, not fatal: %+v, %v", served, err)
	}

	lab.servers[0].Shutdown()
	if _, err := v.ProbeServedKeys("child.parent.test."); err == nil {
		t.Fatal("no answering server at all must fail the probe")
	}
}

// ProbeParentDS now also reports the DS records the parent holds, deduplicated
// across servers, so a takeover can say what the parent trusts.
func TestProbeParentDS_ReportsDSRecords(t *testing.T) {
	lab := newParentLab(t)
	v := lab.validator()
	oldK, newK := testKSK(t, 1), testKSK(t, 2)
	lab.set(lab.v4(), dsWithTTL(oldK, 3600), dsWithTTL(newK, 3600))
	lab.set(lab.v6(), dsWithTTL(oldK, 7200))
	obs, err := v.ProbeParentDS("child.parent.test.", []*dns.DNSKEY{oldK})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs.DSRecords) != 2 {
		t.Fatalf("the union of DS records across servers must be reported once each, got %d", len(obs.DSRecords))
	}
	tags := map[uint16]bool{}
	for _, ds := range obs.DSRecords {
		tags[ds.KeyTag] = true
	}
	if !tags[oldK.KeyTag()] || !tags[newK.KeyTag()] {
		t.Fatalf("DS records %v must cover both keys", obs.DSRecords)
	}
}
