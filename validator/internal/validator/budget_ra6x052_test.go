package validator

import (
	"context"
	"encoding/base64"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// RA6X-052 (Medium): signature candidate search has a shared, bounded work
// budget and a cancellation boundary; exhaustion is an explicit indeterminate
// result, never secure and never a fabricated crypto failure.

func TestRA6X052_DuplicateKeysAndSignaturesDoNotMultiplyWork(t *testing.T) {
	zone := newTestZone(t, "example.com.")
	a := &dns.A{Hdr: rrHdr("www.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	good := zone.signZSK(t, a)
	bad := dns.Copy(good).(*dns.RRSIG)
	junk := make([]byte, 64)
	for i := range junk {
		junk[i] = byte(i)
	}
	bad.Signature = base64.StdEncoding.EncodeToString(junk)

	// 30 copies of the bad signature and 30 copies of the same key, then the
	// genuine signature: without de-duplication this is 30×30 attempts before
	// the valid one is reached.
	records := []dns.RR{a}
	for i := 0; i < 30; i++ {
		records = append(records, dns.Copy(bad))
	}
	records = append(records, good)
	keys := make([]dnspkg.DNSKEYRecord, 0, 30)
	for i := 0; i < 30; i++ {
		keys = append(keys, zone.keyRecords()[1])
	}

	b := newVerifyBudget(context.Background(), 10)
	v, err := verifyRRsetInRecords(b, records, dns.TypeA, keys, "www.example.com.", zone.name)
	if err != nil {
		t.Fatalf("the genuine signature must verify within a small budget after de-duplication: %v", err)
	}
	if v == nil || v.Signature.Signature != good.Signature {
		t.Fatal("the verified signature must be the genuine one")
	}
	if spent := b.Spent(); spent > 2 {
		t.Fatalf("spent %d units; duplicates must collapse to one bad attempt plus one good", spent)
	}
}

func TestRA6X052_ExhaustionIsExplicit(t *testing.T) {
	zone := newTestZone(t, "example.com.")
	a := &dns.A{Hdr: rrHdr("www.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.1")}
	raw := packMsg(t, "www.example.com.", dns.TypeA, dns.RcodeSuccess, []dns.RR{a, zone.signZSK(t, a)}, nil)

	// Zero budget: the very first attempt is refused with the sentinel.
	b := newVerifyBudget(context.Background(), 0)
	if _, err := verifyRRsetFromResponseB(b, raw, dns.TypeA, zone.keyRecords(), "www.example.com.", zone.name, true); !IsBudgetExhausted(err) {
		t.Fatalf("expected the budget sentinel, got %v", err)
	}
	// Once exhausted, every later charge fails too.
	if err := b.charge(1); !IsBudgetExhausted(err) {
		t.Fatalf("an exhausted budget must stay exhausted, got %v", err)
	}

	// Cancellation is a boundary as well.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bc := newVerifyBudget(ctx, 1000)
	if _, err := verifyRRsetFromResponseB(bc, raw, dns.TypeA, zone.keyRecords(), "www.example.com.", zone.name, true); !IsBudgetExhausted(err) || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("a cancelled validation must stop with the sentinel, got %v", err)
	}

	// Denial and leaf verdicts map exhaustion to indeterminate.
	nsec := nsecRR("example.com.", "zzz.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC)
	rawNX := packMsg(t, "nx.example.com.", dns.TypeA, dns.RcodeNameError, nil, []dns.RR{nsec, zone.signZSK(t, nsec)})
	proof := verifyNSECDenialWithRRSIGB(newVerifyBudget(context.Background(), 0), "nx.example.com.", dns.TypeA,
		[]dnspkg.NSECRecord{dnspkg.NSECFromRR(nsec, dnspkg.SectionAuthority)}, zone.keyRecords(), zone.name, rawNX, dns.RcodeNameError)
	if proof.Verified || !isBudgetExhaustedText(proof.Error) {
		t.Fatalf("denial under an exhausted budget must not verify and must say so: %+v", proof)
	}
	rv := &RecordValidation{RecordType: "A", DenialProof: proof, Error: proof.Error}
	if verdict, _ := recordValidationVerdict(rv); verdict != StatusIndeterminate {
		t.Fatalf("exhausted denial verdict = %s, want indeterminate", verdict)
	}
	rv = &RecordValidation{RecordType: "A", Error: "A record RRSIG verification failed: " + budgetExhaustedMessage + " (limit 5 units)"}
	if verdict, _ := recordValidationVerdict(rv); verdict != StatusIndeterminate {
		t.Fatalf("exhausted leaf verdict = %s, want indeterminate", verdict)
	}
	rv = &RecordValidation{RecordType: "A", RRSIGVerified: true, Wildcard: true, WildcardProof: &NSECProof{Error: budgetExhaustedMessage}}
	if verdict, _ := recordValidationVerdict(rv); verdict != StatusIndeterminate {
		t.Fatalf("exhausted wildcard-proof verdict = %s, want indeterminate", verdict)
	}
}

func TestRA6X052_EndToEndBudgetBoundsValidation(t *testing.T) {
	f := newChainFixture(t)
	child := f.addChild(t, "child.test.")
	serveA(t, f.m, child, "www.child.test.")

	// A budget too small for even the DS/DNSKEY step: indeterminate with the
	// resource-limit reason, not secure and not bogus.
	f.v.SetVerificationBudget(1)
	res := f.validate(t, "www.child.test.")
	if res.Result != StatusIndeterminate {
		t.Fatalf("under an exhausted budget the result must be indeterminate, got %s errors=%v", res.Result, res.Errors)
	}
	if !strings.Contains(strings.Join(res.Errors, "\n"), budgetExhaustedMessage) {
		t.Fatalf("the resource limit must be named: %v", res.Errors)
	}

	// The default budget covers a normal chain with a large margin.
	f.v.SetVerificationBudget(0)
	res = f.validate(t, "www.child.test.")
	if res.Result != StatusSecure {
		t.Fatalf("default budget must validate a normal chain, got %s errors=%v", res.Result, res.Errors)
	}
	if spent := f.v.budget.Spent(); spent <= 0 || spent > 50 {
		t.Fatalf("a normal chain spent %d units; expected a small positive amount", spent)
	}
	// Nested alias hops share the same budget.
	serveAlias(t, f.m, child, "alias.child.test.", "www.child.test.")
	res = f.validate(t, "alias.child.test.")
	if res.Result != StatusSecure {
		t.Fatalf("alias validation under the default budget must be secure, got %s", res.Result)
	}
}
