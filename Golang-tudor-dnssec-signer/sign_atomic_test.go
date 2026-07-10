package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// R-002: two processes signing the same zone must not corrupt the published file. With a
// unique temp per writer, the atomic rename always publishes exactly one writer's complete
// output; the file parses cleanly on every iteration and no temp files leak.
func TestWriteSignedZone_ConcurrentUniqueTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.com.zone.signed")
	s := &Signer{}

	mkRecords := func(ip string) []dns.RR {
		soa, err := dns.NewRR("example.com. 3600 IN SOA ns.example.com. admin.example.com. 1 3600 600 86400 3600")
		if err != nil {
			t.Fatal(err)
		}
		ns, err := dns.NewRR("example.com. 3600 IN NS ns.example.com.")
		if err != nil {
			t.Fatal(err)
		}
		a, err := dns.NewRR("example.com. 3600 IN A " + ip)
		if err != nil {
			t.Fatal(err)
		}
		return []dns.RR{soa, ns, a}
	}
	setA := mkRecords("192.0.2.1")
	setB := mkRecords("192.0.2.2")

	for i := 0; i < 100; i++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = s.writeSignedZone("example.com", path, setA) }()
		go func() { defer wg.Done(); _ = s.writeSignedZone("example.com", path, setB) }()
		wg.Wait()

		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("iteration %d: open signed zone: %v", i, err)
		}
		zp := dns.NewZoneParser(f, "example.com.", path)
		for _, ok := zp.Next(); ok; _, ok = zp.Next() {
		}
		perr := zp.Err()
		f.Close()
		if perr != nil {
			t.Fatalf("iteration %d: signed zone did not parse cleanly (corruption): %v", i, perr)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leaked temp file after concurrent writes: %s", e.Name())
		}
	}
}
