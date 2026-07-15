package dns

import "testing"

func TestDialAddr(t *testing.T) {
	cases := map[string]string{
		"198.41.0.4":       "198.41.0.4:53",       // bare IPv4 — the root servers
		"::1":              "[::1]:53",            // bare IPv6 — junia's configured resolver
		"127.0.0.1":        "127.0.0.1:53",        // the built-in default
		"resolver.invalid": "resolver.invalid:53", // bare hostname
		"127.0.0.1:5353":   "127.0.0.1:5353",      // explicit port passes through
		"[::1]:5353":       "[::1]:5353",          // explicit port, IPv6
	}
	for in, want := range cases {
		if got := dialAddr(in); got != want {
			t.Errorf("dialAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
