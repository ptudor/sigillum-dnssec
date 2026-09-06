package dns

import "testing"

func TestQuerierDial(t *testing.T) {
	q := NewQuerier(0)
	cases := map[string]string{
		"198.41.0.4":       "198.41.0.4:53",       // bare IPv4 — the root servers
		"::1":              "[::1]:53",            // bare IPv6 — junia's configured resolver
		"127.0.0.1":        "127.0.0.1:53",        // the built-in default
		"resolver.invalid": "resolver.invalid:53", // bare hostname
		"127.0.0.1:5353":   "127.0.0.1:5353",      // explicit port passes through
		"[::1]:5353":       "[::1]:5353",          // explicit port, IPv6
	}
	for in, want := range cases {
		if got := q.dial(in); got != want {
			t.Errorf("dial(%q) = %q, want %q", in, got, want)
		}
	}

	// RA6X-050: the default-port seam lets a hermetic fixture on an ephemeral
	// port stand in for port-53 servers without touching explicit ports.
	r := NewResolver(0, "127.0.0.1")
	r.SetDefaultPort("5300")
	if got := r.querier.dial("192.0.2.1"); got != "192.0.2.1:5300" {
		t.Errorf("dial with default port 5300 = %q, want 192.0.2.1:5300", got)
	}
	if got := r.querier.dial("192.0.2.1:53"); got != "192.0.2.1:53" {
		t.Errorf("explicit port must pass through the seam, got %q", got)
	}
}
