package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for DNSSEC signing operations
var (
	// Zone metrics
	zonesTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "dnssec_tudor",
		Name:      "zones_total",
		Help:      "Total number of zones being managed",
	})

	zonesHealthy = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "dnssec_tudor",
		Name:      "zones_healthy",
		Help:      "Number of zones in healthy state",
	})

	zonesActionRequired = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "dnssec_tudor",
		Name:      "zones_action_required",
		Help:      "Number of zones requiring action (e.g., DS update)",
	})

	zonesWithErrors = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "dnssec_tudor",
		Name:      "zones_errors",
		Help:      "Number of zones with errors",
	})

	// Signing metrics
	signingOperationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dnssec_tudor",
		Name:      "signing_operations_total",
		Help:      "Total number of signing operations",
	}, []string{"domain", "status"})

	signingDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "dnssec_tudor",
		Name:      "signing_duration_seconds",
		Help:      "Duration of zone signing operations in seconds",
		Buckets:   prometheus.ExponentialBuckets(0.01, 2, 10), // 10ms to ~10s
	}, []string{"domain"})

	lastSigningTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "dnssec_tudor",
		Name:      "last_signing_timestamp_seconds",
		Help:      "Unix timestamp of the last successful signing operation",
	}, []string{"domain"})

	signatureExpiryTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "dnssec_tudor",
		Name:      "signature_expiry_timestamp_seconds",
		Help:      "Unix timestamp when signatures expire for a zone",
	}, []string{"domain"})

	// Key metrics
	kskExpiryTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "dnssec_tudor",
		Name:      "ksk_expiry_timestamp_seconds",
		Help:      "Unix timestamp when KSK expires for a zone",
	}, []string{"domain"})

	zskExpiryTimestamp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "dnssec_tudor",
		Name:      "zsk_expiry_timestamp_seconds",
		Help:      "Unix timestamp when ZSK expires for a zone",
	}, []string{"domain"})

	// Rollover metrics
	rolloversInProgress = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "dnssec_tudor",
		Name:      "rollover_in_progress",
		Help:      "Whether a rollover is in progress (1) or not (0)",
	}, []string{"domain", "type"})

	rolloverOperationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dnssec_tudor",
		Name:      "rollover_operations_total",
		Help:      "Total number of rollover operations",
	}, []string{"domain", "type", "action"})

	// Hook metrics
	hookExecutionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "dnssec_tudor",
		Name:      "hook_executions_total",
		Help:      "Total number of hook executions",
	}, []string{"hook", "status"})

	hookDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "dnssec_tudor",
		Name:      "hook_duration_seconds",
		Help:      "Duration of hook executions in seconds",
		Buckets:   prometheus.ExponentialBuckets(0.01, 2, 12), // 10ms to ~40s
	}, []string{"hook"})
)

// UpdateZoneMetrics updates all zone-related metrics from state
func UpdateZoneMetrics(state *State) {
	state.mu.RLock()
	defer state.mu.RUnlock()

	var total, healthy, actionRequired, errors int

	for domain, zone := range state.Zones {
		total++
		status := zone.Status()
		switch status {
		case "healthy":
			healthy++
		case "action_required":
			actionRequired++
		case "error":
			errors++
		}

		// Update per-zone metrics
		if !zone.LastSigned.IsZero() {
			lastSigningTimestamp.WithLabelValues(domain).Set(float64(zone.LastSigned.Unix()))
		}
		if !zone.SignaturesExp.IsZero() {
			signatureExpiryTimestamp.WithLabelValues(domain).Set(float64(zone.SignaturesExp.Unix()))
		}
		if zone.KSK != nil && !zone.KSK.Expires.IsZero() {
			kskExpiryTimestamp.WithLabelValues(domain).Set(float64(zone.KSK.Expires.Unix()))
		}
		if zone.ZSK != nil && !zone.ZSK.Expires.IsZero() {
			zskExpiryTimestamp.WithLabelValues(domain).Set(float64(zone.ZSK.Expires.Unix()))
		}

		// Rollover status
		if zone.Rollover != nil {
			rolloversInProgress.WithLabelValues(domain, zone.Rollover.Type).Set(1)
		} else {
			// Reset all rollover types to 0
			rolloversInProgress.WithLabelValues(domain, "ksk").Set(0)
			rolloversInProgress.WithLabelValues(domain, "zsk").Set(0)
			rolloversInProgress.WithLabelValues(domain, "algorithm").Set(0)
		}
	}

	zonesTotal.Set(float64(total))
	zonesHealthy.Set(float64(healthy))
	zonesActionRequired.Set(float64(actionRequired))
	zonesWithErrors.Set(float64(errors))
}

// RecordSigningOperation records metrics for a signing operation
func RecordSigningOperation(domain string, durationSeconds float64, success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	signingOperationsTotal.WithLabelValues(domain, status).Inc()
	signingDurationSeconds.WithLabelValues(domain).Observe(durationSeconds)
}

// RecordHookExecution records metrics for a hook execution
func RecordHookExecution(hook string, durationSeconds float64, success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	hookExecutionsTotal.WithLabelValues(hook, status).Inc()
	hookDurationSeconds.WithLabelValues(hook).Observe(durationSeconds)
}

// RecordRolloverOperation records a rollover operation
func RecordRolloverOperation(domain, rolloverType, action string) {
	rolloverOperationsTotal.WithLabelValues(domain, rolloverType, action).Inc()
}
