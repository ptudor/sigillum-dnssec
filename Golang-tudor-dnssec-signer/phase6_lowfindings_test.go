package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/ptudor/dnssec-tudor/internal/config"
)

// R-060: an unsupported registrar digest_type is rejected at validation, not
// silently coerced to SHA-256.
func TestR060_ValidateRejectsInvalidDigestType(t *testing.T) {
	for _, dt := range []int{1, 3, 5, 255, -1} {
		c := config.DefaultConfig()
		c.Registrar.DigestTypeVal = dt
		if err := c.Validate(); err == nil {
			t.Errorf("digest_type=%d must be rejected", dt)
		}
	}
	for _, dt := range []int{0, 2, 4} {
		c := config.DefaultConfig()
		c.Registrar.DigestTypeVal = dt
		if err := c.Validate(); err != nil {
			t.Errorf("digest_type=%d must be accepted: %v", dt, err)
		}
	}
}

// R-021: a direct rollover type transition (ksk -> algorithm) must leave exactly
// one type series at 1 — the old type must be zeroed.
func TestR021_RolloverMetricsNoStaleType(t *testing.T) {
	const domain = "r021.example"
	st := NewState("/tmp/does-not-matter")

	gauge := func(rtype string) float64 {
		m := &dto.Metric{}
		g, err := rolloversInProgress.GetMetricWithLabelValues(domain, rtype)
		if err != nil {
			t.Fatal(err)
		}
		if err := g.(prometheus.Metric).Write(m); err != nil {
			t.Fatal(err)
		}
		return m.GetGauge().GetValue()
	}

	// KSK rollover in progress.
	st.SetZone(domain, &ZoneState{Rollover: &RolloverState{Type: "ksk"}})
	UpdateZoneMetrics(st)
	if gauge("ksk") != 1 || gauge("algorithm") != 0 || gauge("zsk") != 0 {
		t.Fatalf("after ksk: ksk=%v algorithm=%v zsk=%v", gauge("ksk"), gauge("algorithm"), gauge("zsk"))
	}

	// Transition directly to an algorithm rollover — ksk must be zeroed.
	st.UpdateZone(domain, func(zs *ZoneState) { zs.Rollover = &RolloverState{Type: "algorithm"} })
	UpdateZoneMetrics(st)
	if gauge("algorithm") != 1 || gauge("ksk") != 0 || gauge("zsk") != 0 {
		t.Fatalf("after algorithm: algorithm=%v ksk=%v zsk=%v (ksk should be 0)", gauge("algorithm"), gauge("ksk"), gauge("zsk"))
	}

	// No rollover — all zeroed.
	st.UpdateZone(domain, func(zs *ZoneState) { zs.Rollover = nil })
	UpdateZoneMetrics(st)
	if gauge("ksk") != 0 || gauge("zsk") != 0 || gauge("algorithm") != 0 {
		t.Fatalf("after nil: expected all zero, got ksk=%v zsk=%v algorithm=%v", gauge("ksk"), gauge("zsk"), gauge("algorithm"))
	}
}
