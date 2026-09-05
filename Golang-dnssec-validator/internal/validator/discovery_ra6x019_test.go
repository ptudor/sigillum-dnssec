package validator

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// RA6X-019 (Medium), validator side: the DS query for a delegation whose
// parent skips labels goes to the actual parent from the zone walk, and
// cancellation is bounded.
func TestRA6X019_LabelSkippingDelegationUsesActualParent(t *testing.T) {
	m := newMockDNS(t)
	parent := newTestZone(t, "example.")
	child := newTestZone(t, "child.branch.example.")
	m.serveInfra("example.")
	m.serveInfra("child.branch.example.")
	parent.serveDS(t, m, child, nil, nil)
	child.serveDNSKEY(t, m)

	v := m.newValidator()
	zr, err := v.validateZone(testCtx(t), "child.branch.example.", []string{".", "example.", "child.branch.example."}, parent.keyRecords(), false)
	if err != nil {
		t.Fatalf("validateZone: %v", err)
	}
	if zr.Status != StatusSecure {
		t.Fatalf("label-skipping delegation must validate against its actual parent: %s errors=%v", zr.Status, zr.Errors)
	}
	if zr.DSValidation == nil || zr.DSValidation.ParentZone != "example." {
		t.Fatalf("DS validation parent = %+v, want example.", zr.DSValidation)
	}
	sawDS, sawBranchNS := false, false
	for _, q := range m.questions() {
		if q.Qtype == dns.TypeDS && dns.CanonicalName(q.Name) == "child.branch.example." {
			sawDS = true
		}
		if q.Qtype == dns.TypeNS && dns.CanonicalName(q.Name) == "branch.example." {
			sawBranchNS = true
		}
	}
	if !sawDS {
		t.Fatal("no DS query for the child was sent")
	}
	if sawBranchNS {
		t.Fatal("the DS query was directed via the non-existent intermediate name branch.example.")
	}
}

func TestRA6X019_CancellationIsBounded(t *testing.T) {
	m := newMockDNS(t)
	m.drop("test.", dns.TypeNS)
	v := m.newValidatorWithTimeout(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := v.resolver.DiscoverZoneCuts(ctx, "www.child.test.")
	if err == nil {
		t.Fatal("expected a context error from a cancelled discovery")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("discovery did not honour cancellation promptly: %v", time.Since(start))
	}
}
