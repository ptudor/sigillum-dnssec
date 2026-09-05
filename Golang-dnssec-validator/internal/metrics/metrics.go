package metrics

import (
	"expvar"

	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus metrics
var (
	promValidationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dnssec_validator_validations_total",
			Help: "Total number of DNSSEC validations",
		},
		[]string{"status"}, // secure, insecure, bogus, indeterminate
	)

	promValidationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dnssec_validator_validation_duration_seconds",
			Help:    "DNSSEC validation duration in seconds",
			Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 15, 30},
		},
		[]string{"status"},
	)

	promAPIRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dnssec_validator_api_requests_total",
			Help: "Total number of API requests",
		},
		[]string{"endpoint", "method", "status"},
	)

	promAPIRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dnssec_validator_api_request_duration_seconds",
			Help:    "API request duration in seconds",
			Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		},
		[]string{"endpoint"},
	)

	promRateLimitHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dnssec_validator_rate_limit_hits_total",
			Help: "Total number of requests rejected by rate limiting",
		},
	)

	promActiveValidations = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dnssec_validator_active_validations",
			Help: "Number of currently active validations",
		},
	)

	promActiveSSEConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dnssec_validator_active_sse_connections",
			Help: "Number of currently active SSE connections",
		},
	)
)

// expvar metrics for simple debugging
var (
	expvarValidationsTotal     = expvar.NewInt("dnssec_validator_validations_total")
	expvarValidationsSecure    = expvar.NewInt("dnssec_validator_validations_secure")
	expvarValidationsInsecure  = expvar.NewInt("dnssec_validator_validations_insecure")
	expvarValidationsBogus     = expvar.NewInt("dnssec_validator_validations_bogus")
	expvarRateLimitHits        = expvar.NewInt("dnssec_validator_rate_limit_hits")
	expvarActiveSSEConnections = expvar.NewInt("dnssec_validator_active_sse_connections")
)

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(promValidationsTotal)
	prometheus.MustRegister(promValidationDuration)
	prometheus.MustRegister(promAPIRequests)
	prometheus.MustRegister(promAPIRequestDuration)
	prometheus.MustRegister(promRateLimitHits)
	prometheus.MustRegister(promActiveValidations)
	prometheus.MustRegister(promActiveSSEConnections)
}

// RegisterRootAnchorMetrics installs scrape-time gauges for root anchor freshness
// and availability. ageFn returns the age (seconds) of the last successfully
// loaded anchor set, or NaN if none has ever loaded; activeFn returns the count
// of currently-active pinned anchors — the ones that can actually establish
// root trust (RA6X-008). Computing at scrape time (R-055) avoids the
// frozen/zero-on-startup behavior of a Set()-at-load gauge and never resets age
// after a failed refresh (the source timestamp only advances on success).
func RegisterRootAnchorMetrics(ageFn func() float64, activeFn func() float64) {
	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "dnssec_validator_root_anchors_age_seconds",
			Help: "Age in seconds of the last successfully loaded root anchor set (NaN if never loaded)",
		}, ageFn))
	prometheus.MustRegister(prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "dnssec_validator_root_anchors_active",
			Help: "Number of currently-active (validity window open), pinned root trust anchors able to establish root trust",
		}, activeFn))
}

// RecordValidation records metrics for a DNSSEC validation
func RecordValidation(status string, durationSec float64) {
	promValidationsTotal.WithLabelValues(status).Inc()
	promValidationDuration.WithLabelValues(status).Observe(durationSec)

	expvarValidationsTotal.Add(1)
	switch status {
	case "secure":
		expvarValidationsSecure.Add(1)
	case "insecure":
		expvarValidationsInsecure.Add(1)
	case "bogus":
		expvarValidationsBogus.Add(1)
	}
}

// RecordAPIRequest records an API request
func RecordAPIRequest(endpoint, method, status string, durationSec float64) {
	promAPIRequests.WithLabelValues(endpoint, method, status).Inc()
	promAPIRequestDuration.WithLabelValues(endpoint).Observe(durationSec)
}

// RecordRateLimitHit records a rate limit rejection
func RecordRateLimitHit() {
	promRateLimitHits.Inc()
	expvarRateLimitHits.Add(1)
}

// IncrementActiveValidations increments the in-flight validation gauge
func IncrementActiveValidations() {
	promActiveValidations.Inc()
}

// DecrementActiveValidations decrements the in-flight validation gauge
func DecrementActiveValidations() {
	promActiveValidations.Dec()
}

// IncrementActiveSSEConnections increments the active SSE connection count
func IncrementActiveSSEConnections() {
	promActiveSSEConnections.Inc()
	expvarActiveSSEConnections.Add(1)
}

// DecrementActiveSSEConnections decrements the active SSE connection count
func DecrementActiveSSEConnections() {
	promActiveSSEConnections.Dec()
	expvarActiveSSEConnections.Add(-1)
}
