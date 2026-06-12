package main

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

	promRootAnchorsAge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "dnssec_validator_root_anchors_age_seconds",
			Help: "Age of loaded root anchors in seconds",
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
	prometheus.MustRegister(promRootAnchorsAge)
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

// SetRootAnchorsAge sets the age of loaded root anchors
func SetRootAnchorsAge(ageSec float64) {
	promRootAnchorsAge.Set(ageSec)
}
