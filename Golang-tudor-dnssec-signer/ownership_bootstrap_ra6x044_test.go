package main

import (
	"strings"
	"testing"

	"github.com/ptudor/dnssec-tudor/internal/fsutil"
)

// RA6X-044: a mutating command run as root against a missing data_dir is
// refused with the explicit bootstrap procedure; an existing tree passes. (A
// non-root test process never observes the "missing" status through
// InitOwnershipTarget, so the mapping is exercised via the message and the
// existing-tree path; the status logic itself is covered in fsutil.)
func TestRA6X044_BootstrapMessage(t *testing.T) {
	if err := checkOwnershipBootstrap(t.TempDir()); err != nil {
		t.Fatalf("existing data_dir must pass: %v", err)
	}
	msg := strings.ToLower(fsutil.BootstrapInstructions("/var/lib/dnssec-tudor"))
	for _, want := range []string{"install -d", "root-only", "daemon account", "/var/lib/dnssec-tudor"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("bootstrap message must mention %q: %s", want, msg)
		}
	}
}
