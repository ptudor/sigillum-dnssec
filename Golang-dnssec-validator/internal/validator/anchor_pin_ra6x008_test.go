package validator

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// The IANA root KSK-2017 public key (tag 20326). Its SHA-256 DS digest is the
// constant this build pins; the test below proves that before relying on it.
const realKSK2017PublicKey = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="

const realKSK2017Digest = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

// genuineRootKSK returns the real KSK-2017 as a wire DNSKEY and parsed record,
// after proving its DS digest equals the pinned constant.
func genuineRootKSK(t *testing.T) (*dns.DNSKEY, dnspkg.DNSKEYRecord) {
	t.Helper()
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: ".", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 172800},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.RSASHA256,
		PublicKey: realKSK2017PublicKey,
	}
	if k.KeyTag() != 20326 {
		t.Fatalf("embedded KSK-2017 key tag = %d, want 20326", k.KeyTag())
	}
	rec := dnspkg.DNSKEYFromRR(k, dnspkg.SectionAnswer)
	digest, err := ComputeDSDigestFromDNSKEY(".", rec, 2)
	if err != nil {
		t.Fatalf("compute DS: %v", err)
	}
	if !strings.EqualFold(digest, realKSK2017Digest) {
		t.Fatalf("embedded KSK-2017 digest %s != pinned %s", digest, realKSK2017Digest)
	}
	if !dnspkg.IsPinnedRootAnchor(dnspkg.Anchor{KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: digest}) {
		t.Fatal("KSK-2017 must be pinned")
	}
	return k, rec
}

// mixedAnchorSet returns the genuine pinned KSK-2017 anchor plus an attacker
// anchor whose digest genuinely matches the attacker's root key — the "mixed
// anchor document" of RA6X-008.
func mixedAnchorSet(t *testing.T, attacker dnspkg.DNSKEYRecord) *dnspkg.RootAnchors {
	t.Helper()
	attackerDigest, err := ComputeDSDigestFromDNSKEY(".", attacker, 2)
	if err != nil {
		t.Fatalf("compute attacker DS: %v", err)
	}
	return &dnspkg.RootAnchors{Zone: ".", Anchors: []dnspkg.Anchor{
		{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: "2017-02-02T00:00:00Z"},
		{ID: "attacker", KeyTag: int(attacker.KeyTag), Algorithm: int(attacker.Algorithm), DigestType: 2, Digest: attackerDigest, ValidFrom: "2017-02-02T00:00:00Z"},
	}}
}

// RA6X-008 (Critical), helper level: with a mixed anchor set, only the genuine
// pinned key may authenticate the root DNSKEY RRset. The attacker's key matches
// its own (unpinned) anchor by digest and must still contribute nothing.
func TestRA6X008_MixedAnchorsAuthenticateOnlyPinnedKey(t *testing.T) {
	genuineKSK, genuineRec := genuineRootKSK(t)
	attacker := newTestZone(t, ".")
	attackerRec := dnspkg.DNSKEYFromRR(attacker.ksk, dnspkg.SectionAnswer)
	anchors := mixedAnchorSet(t, attackerRec)
	active := dnspkg.GetActivePinnedAnchors(anchors)
	if len(active) != 1 || active[0].KeyTag != 20326 {
		t.Fatalf("active pinned anchors = %+v, want only KSK-2017", active)
	}

	rrset := []dnspkg.DNSKEYRecord{genuineRec, attackerRec}

	// The existential root check passes because the genuine key is present…
	if link, err := VerifyRootTrustAnchor(rrset, dnspkg.GetActiveAnchors(anchors)); err != nil || !link.DSMatchesKSK {
		t.Fatalf("genuine pinned key present: root anchor check should pass, got err=%v link=%+v", err, link)
	}
	// …but the set of keys allowed to sign the RRset must contain the pinned key only.
	authed := CollectAnchorMatchedKeys(rrset, dnspkg.GetActiveAnchors(anchors))
	if len(authed) != 1 || authed[0].KeyTag != 20326 {
		t.Fatalf("anchor-matched keys = %+v, want only the pinned KSK-2017", authed)
	}

	// A signature over the mixed RRset made only by the attacker's key must be rejected.
	wire := []dns.RR{genuineKSK, attacker.ksk}
	sig := attacker.signKSK(t, wire...)
	msg := new(dns.Msg)
	msg.SetQuestion(".", dns.TypeDNSKEY)
	msg.Answer = append(wire, sig)
	raw, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if _, err := VerifyDNSKEYRRsetFromResponse(raw, ".", authed); err == nil {
		t.Fatal("root DNSKEY RRset signed only by the attacker's (unpinned-anchor) key was accepted")
	}
}

// RA6X-008, caller level: the same attack through the real root branch of
// validateZone with the hermetic harness serving the root zone.
func TestRA6X008_RootZoneRejectsMixedAnchorAttack(t *testing.T) {
	genuineKSK, _ := genuineRootKSK(t)
	attacker := newTestZone(t, ".")
	attackerRec := dnspkg.DNSKEYFromRR(attacker.ksk, dnspkg.SectionAnswer)

	m := newMockDNS(t)
	wire := []dns.RR{genuineKSK, attacker.ksk, attacker.zsk}
	m.answer(".", dns.TypeDNSKEY, append(wire, attacker.signKSK(t, wire...))...)

	v := m.newValidator()
	v.SetAnchors(mixedAnchorSet(t, attackerRec))

	zr, err := v.validateZone(testCtx(t), ".", []string{"."}, nil, false)
	if err != nil {
		t.Fatalf("validateZone: %v", err)
	}
	if zr.Status != StatusBogus {
		t.Fatalf("mixed-anchor root attack must be bogus, got %s errors=%v", zr.Status, zr.Errors)
	}

	// With no pinned anchor active at all the result is indeterminate (local
	// trust failure), never secure.
	future := "2999-01-01T00:00:00Z"
	v.SetAnchors(&dnspkg.RootAnchors{Zone: ".", Anchors: []dnspkg.Anchor{
		{ID: "KSK-2017", KeyTag: 20326, Algorithm: 8, DigestType: 2, Digest: realKSK2017Digest, ValidFrom: future},
		{ID: "attacker", KeyTag: int(attackerRec.KeyTag), Algorithm: 13, DigestType: 2, Digest: mixedAnchorSet(t, attackerRec).Anchors[1].Digest, ValidFrom: "2017-02-02T00:00:00Z"},
	}})
	zr, err = v.validateZone(testCtx(t), ".", []string{"."}, nil, false)
	if err != nil {
		t.Fatalf("validateZone: %v", err)
	}
	if zr.Status != StatusIndeterminate {
		t.Fatalf("root with only an unpinned active anchor must be indeterminate, got %s errors=%v", zr.Status, zr.Errors)
	}
}
