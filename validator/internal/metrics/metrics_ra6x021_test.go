package metrics

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// Thousands of distinct request methods must not create thousands of series:
// the method label stays within the fixed known set plus OTHER (RA6X-021).
func TestRecordAPIRequest_BoundedMethodLabel(t *testing.T) {
	const endpoint = "/api/validate-bounded-test"
	for i := 0; i < 3000; i++ {
		RecordAPIRequest(endpoint, fmt.Sprintf("M%dXYZ", i), "405", 0.001)
	}
	for _, m := range []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"} {
		RecordAPIRequest(endpoint, m, "200", 0.001)
	}
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	methods := map[string]bool{}
	var other float64
	for _, f := range families {
		if f.GetName() != "sigillum_validator_api_requests_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			var ep, method string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "endpoint":
					ep = l.GetValue()
				case "method":
					method = l.GetValue()
				}
			}
			if ep != endpoint {
				continue
			}
			methods[method] = true
			if method == "OTHER" {
				other += m.GetCounter().GetValue()
			}
		}
	}
	if len(methods) > len(knownMethods)+1 {
		t.Fatalf("method label values must stay bounded, got %d: %v", len(methods), methods)
	}
	if other != 3000 {
		t.Fatalf("invented methods must be counted under OTHER, got %v", other)
	}
	for _, m := range []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"} {
		if !methods[m] {
			t.Fatalf("known method %s must keep its own label", m)
		}
	}
}
