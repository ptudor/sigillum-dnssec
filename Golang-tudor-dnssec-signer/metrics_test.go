package main

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// gaugeValue gathers the default registry and returns the value of a label-less
// gauge by its fully-qualified name (namespace + "_" + name). Using the
// gatherer directly avoids pulling in the testutil package's extra deps.
func gaugeValue(t *testing.T, name string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		if m := mf.GetMetric(); len(m) > 0 {
			return m[0].GetGauge().GetValue()
		}
	}
	return 0
}

// signatureExpirySeriesExists reports whether a per-domain
// signature_expiry_timestamp series is currently exported for the given domain.
// It gathers the default registry so the check is precise to the domain label
// and isolated from series other tests may have created.
func signatureExpirySeriesExists(t *testing.T, domain string) bool {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "dnssec_tudor_signature_expiry_timestamp_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "domain" && lp.GetValue() == domain {
					return true
				}
			}
		}
	}
	return false
}

// TestUpdateZoneMetrics_WarningCounted (R-069): a warning-status zone is
// counted in its own gauge so the summary balances (total == healthy +
// action_required + warning + errors), instead of vanishing.
func TestUpdateZoneMetrics_WarningCounted(t *testing.T) {
	state := NewState(t.TempDir() + "/state.json")
	state.SetZone("healthy.example.", &ZoneState{Path: "/z/healthy"})
	state.SetZone("warn.example.", &ZoneState{Path: "/z/warn", Warnings: []string{"ZSK expires soon"}})

	UpdateZoneMetrics(state)

	if got := gaugeValue(t, "dnssec_tudor_zones_warning"); got != 1 {
		t.Errorf("zones_warning = %v, want 1", got)
	}
	total := gaugeValue(t, "dnssec_tudor_zones_total")
	sum := gaugeValue(t, "dnssec_tudor_zones_healthy") + gaugeValue(t, "dnssec_tudor_zones_action_required") +
		gaugeValue(t, "dnssec_tudor_zones_warning") + gaugeValue(t, "dnssec_tudor_zones_errors")
	if total != sum {
		t.Errorf("summary gauges do not balance: total=%v, healthy+action+warning+errors=%v", total, sum)
	}
}

// TestUpdateZoneMetrics_RemovedZoneSeriesDeleted (R-042): once a zone leaves
// state, its per-domain series (here the signature-expiry gauge) is deleted on
// the next update — otherwise a frozen past-expiry gauge is a permanent false
// "expired" alert.
func TestUpdateZoneMetrics_RemovedZoneSeriesDeleted(t *testing.T) {
	const domain = "r042-delete-me.example."
	state := NewState(t.TempDir() + "/state.json")
	state.SetZone(domain, &ZoneState{Path: "/z/x", SignaturesExp: time.Now().Add(24 * time.Hour)})

	UpdateZoneMetrics(state)
	if !signatureExpirySeriesExists(t, domain) {
		t.Fatalf("expected a signature_expiry series for %s after it was added", domain)
	}

	// Remove the zone and update again — the series must be gone.
	state.RemoveZone(domain)
	UpdateZoneMetrics(state)
	if signatureExpirySeriesExists(t, domain) {
		t.Errorf("signature_expiry series for %s was not deleted after the zone left state", domain)
	}
}
