package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// TestBINDRSAImportInterop is enabled explicitly by the dedicated CI job. It
// uses keys emitted by BIND itself, runs the compiled CLI in fresh processes,
// and asks BIND to verify Sigillum's output. The ordinary unit-test jobs do not
// need BIND installed.
func TestBINDRSAImportInterop(t *testing.T) {
	if os.Getenv("SIGILLUM_BIND_INTEROP") != "1" {
		t.Skip("set SIGILLUM_BIND_INTEROP=1 to run the BIND interoperability test")
	}
	for _, tool := range []string{"dnssec-keygen", "dnssec-verify"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("SIGILLUM_BIND_INTEROP=1 requires %s: %v", tool, err)
		}
	}

	root := t.TempDir()
	binary := os.Getenv("SIGILLUM_SIGNER_BINARY")
	if binary == "" {
		binary = filepath.Join(root, "sigillum-signer")
		bindInteropCommand(t, "go", "build", "-o", binary, ".")
	} else if _, err := os.Stat(binary); err != nil {
		t.Fatalf("SIGILLUM_SIGNER_BINARY %s is not usable: %v", binary, err)
	}

	for _, tc := range []struct {
		name      string
		algorithm string
		dnsAlg    uint8
		rollover  bool
	}{
		{name: "RSASHA256", algorithm: "RSASHA256", dnsAlg: dns.RSASHA256, rollover: true},
		{name: "RSASHA512", algorithm: "RSASHA512", dnsAlg: dns.RSASHA512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			domain := strings.ToLower(tc.name) + ".example"
			work := filepath.Join(root, strings.ToLower(tc.name))
			keysDir := filepath.Join(work, "bind-keys")
			dataDir := filepath.Join(work, "data")
			outputDir := filepath.Join(work, "signed")
			for _, dir := range []string{keysDir, dataDir, outputDir} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}

			// These are BIND's traditional defaults for the two roles: a
			// 1024-bit ZSK and a 2048-bit KSK.
			bindInteropKeygen(t, keysDir, domain, tc.algorithm, 1024, false)
			bindInteropKeygen(t, keysDir, domain, tc.algorithm, 2048, true)
			candidates, err := signerpkg.ScanBindKeys(keysDir, domain)
			if err != nil {
				t.Fatal(err)
			}
			ksk, zsk := bindInteropPair(t, candidates, tc.dnsAlg)

			zonePath := filepath.Join(work, "zone.db")
			zone := fmt.Sprintf(`$ORIGIN %[1]s.
$TTL 300
@ IN SOA ns.%[1]s. hostmaster.%[1]s. 2026091501 3600 600 86400 300
@ IN NS ns.%[1]s.
ns IN A 192.0.2.1
www IN A 192.0.2.2
`, domain)
			if err := os.WriteFile(zonePath, []byte(zone), 0o600); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(work, "config.toml")
			configText := fmt.Sprintf("output_dir = %q\ndata_dir = %q\n\n[dnssec]\npublication = \"immediate\"\n", outputDir, dataDir)
			if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
				t.Fatal(err)
			}

			bindInteropSigner(t, binary, configPath, "import", domain, zonePath, "--keys-dir", keysDir, "--offline")
			signedPath := filepath.Join(outputDir, domain+".zone.signed")
			bindInteropVerify(t, domain, signedPath)
			bindInteropAssertLiveKey(t, dataDir, domain, "ksk", ksk.Tag, tc.dnsAlg, 2048)
			bindInteropAssertLiveKey(t, dataDir, domain, "zsk", zsk.Tag, tc.dnsAlg, 1024)

			// A new CLI process must reload the converted private files and
			// produce a zone BIND still accepts.
			bindInteropSigner(t, binary, configPath, "resign", domain)
			bindInteropVerify(t, domain, signedPath)

			if tc.rollover {
				bindInteropZSKRollover(t, binary, configPath, dataDir, domain, signedPath, zsk.Tag, tc.dnsAlg)
			}
		})
	}
}

func bindInteropKeygen(t *testing.T, dir, domain, algorithm string, bits int, ksk bool) {
	t.Helper()
	args := []string{"-q", "-K", dir, "-a", algorithm, "-b", strconv.Itoa(bits), "-n", "ZONE"}
	if ksk {
		args = append(args, "-f", "KSK")
	}
	args = append(args, domain)
	bindInteropCommand(t, "dnssec-keygen", args...)
}

func bindInteropPair(t *testing.T, candidates []*signerpkg.ImportCandidate, algorithm uint8) (ksk, zsk *signerpkg.ImportCandidate) {
	t.Helper()
	for _, candidate := range candidates {
		if !candidate.Usable() {
			t.Fatalf("BIND key %s was not importable: %s", candidate.Name(), candidate.Problem)
		}
		if candidate.Algorithm != algorithm {
			t.Fatalf("BIND key %s algorithm = %d, want %d", candidate.Name(), candidate.Algorithm, algorithm)
		}
		switch candidate.Role {
		case "ksk":
			ksk = candidate
		case "zsk":
			zsk = candidate
		}
	}
	if len(candidates) != 2 || ksk == nil || zsk == nil {
		t.Fatalf("BIND generated candidates = %+v, want one KSK and one ZSK", candidates)
	}
	if ksk.Bits != 2048 || zsk.Bits != 1024 {
		t.Fatalf("BIND key sizes: KSK=%d ZSK=%d, want 2048/1024", ksk.Bits, zsk.Bits)
	}
	return ksk, zsk
}

func bindInteropSigner(t *testing.T, binary, configPath string, args ...string) {
	t.Helper()
	commandArgs := []string{"--config", configPath, "--log-level", "error"}
	commandArgs = append(commandArgs, args...)
	bindInteropCommand(t, binary, commandArgs...)
}

func bindInteropVerify(t *testing.T, domain, signedPath string) {
	t.Helper()
	bindInteropCommand(t, "dnssec-verify", "-o", domain, signedPath)
}

func bindInteropAssertLiveKey(t *testing.T, dataDir, domain, role string, tag uint16, algorithm uint8, bits int) {
	t.Helper()
	path := filepath.Join(dataDir, "keys", domain+"."+role+".key")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := signerpkg.ParseDNSKEYFromFile(string(contents))
	if err != nil {
		t.Fatal(err)
	}
	if key.KeyTag() != tag || key.Algorithm != algorithm || signerpkg.RSAKeyBits(key) != bits {
		t.Fatalf("live %s = tag %d algorithm %d bits %d, want %d/%d/%d", role, key.KeyTag(), key.Algorithm, signerpkg.RSAKeyBits(key), tag, algorithm, bits)
	}
}

func bindInteropZSKRollover(t *testing.T, binary, configPath, dataDir, domain, signedPath string, oldTag uint16, algorithm uint8) {
	t.Helper()
	statePath := filepath.Join(dataDir, "state.json")
	state, err := statepkg.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	zone := state.GetZone(domain)
	if zone == nil || zone.ZSK == nil || zone.ZSK.ID != oldTag {
		t.Fatalf("state before rollover has unexpected ZSK: %+v", zone)
	}
	state.Mutate(func() { zone.ZSK.Expires = time.Now().UTC().Add(-time.Hour) })
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	// The first pass starts the rollover. The second publishes the
	// pre-published key set requested by the rollover record.
	bindInteropSigner(t, binary, configPath, "sign")
	state, err = statepkg.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	rollover := state.GetZone(domain).Rollover
	if rollover == nil || rollover.Type != "zsk" || rollover.State != statepkg.ZSKRolloverStatePrePublish || rollover.OldKeyID != oldTag {
		t.Fatalf("RSA ZSK rollover did not enter pre-publish: %+v", rollover)
	}
	bindInteropAssertLiveKey(t, dataDir, domain, "zsk", rollover.NewKeyID, algorithm, 2048)

	bindInteropSigner(t, binary, configPath, "sign")
	bindInteropVerify(t, domain, signedPath)
	tags := publishedTags(t, signedPath, domain)
	if !tags[oldTag] || !tags[rollover.NewKeyID] {
		t.Fatalf("pre-publish DNSKEY tags = %v, want old %d and new %d", tags, oldTag, rollover.NewKeyID)
	}
}

func bindInteropCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}
