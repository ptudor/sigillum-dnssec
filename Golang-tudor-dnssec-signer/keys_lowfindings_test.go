package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

// TestExistingKeyTags (R-029): the collision set includes the live KSK/ZSK tags
// and any backed-up key file's tag, and tagInUse reports membership.
func TestExistingKeyTags(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	kg := NewKeyGenerator(cfg)

	ksk, err := kg.GenerateKSK("example.com")
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK("example.com")
	if err != nil {
		t.Fatal(err)
	}

	// A backup file whose tag is encoded in the filename.
	backupTag := uint16(40000)
	backupFile := filepath.Join(cfg.KeysDir(), fmt.Sprintf("example.com.ksk.%d.key", backupTag))
	if err := os.WriteFile(backupFile, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}

	tags := kg.existingKeyTags("example.com")
	for _, want := range []uint16{ksk.ID, zsk.ID, backupTag} {
		if !tagInUse(want, tags) {
			t.Errorf("tag %d should be reported in use", want)
		}
	}

	// A tag not in the set is free.
	var free uint16 = 1
	for tags[free] {
		free++
	}
	if tagInUse(free, tags) {
		t.Errorf("free tag %d must not be reported in use", free)
	}
}

// TestBackupKey_RefusesDifferingBackup (R-029): backupKey must not overwrite an
// existing backup that holds different key material (a tag collision), but an
// identical re-backup is idempotent.
func TestBackupKey_RefusesDifferingBackup(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	kg := NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK("example.com")
	if err != nil {
		t.Fatal(err)
	}
	rm := NewRolloverManager(cfg, NewState(cfg.StatePath()))

	backupBase := filepath.Join(cfg.KeysDir(), fmt.Sprintf("example.com.ksk.%d", ksk.ID))

	// Pre-seed a DIFFERENT backup at the same <type>.<tag> name.
	if err := os.WriteFile(backupBase+".key", []byte("DIFFERENT CONTENT"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rm.backupKey("example.com", "ksk", ksk.ID); err == nil {
		t.Fatal("backupKey must refuse to overwrite a differing backup")
	}
	if data, _ := os.ReadFile(backupBase + ".key"); string(data) != "DIFFERENT CONTENT" {
		t.Error("the differing backup was overwritten")
	}

	// With no conflicting backup, a first backup then an identical re-backup both
	// succeed (idempotent).
	os.Remove(backupBase + ".key")
	if err := rm.backupKey("example.com", "ksk", ksk.ID); err != nil {
		t.Fatalf("first backup: %v", err)
	}
	if err := rm.backupKey("example.com", "ksk", ksk.ID); err != nil {
		t.Fatalf("idempotent re-backup must succeed: %v", err)
	}
}

// TestValidateLoadedKey (R-061): a loaded key must match the domain, role, and a
// supported algorithm, so a wrong file (bad owner, ZSK-in-KSK-slot, unsupported
// algorithm) is rejected rather than used silently.
func TestValidateLoadedKey(t *testing.T) {
	mk := func(name string, flags uint16, alg uint8) *dns.DNSKEY {
		return &dns.DNSKEY{
			Hdr:       dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
			Flags:     flags,
			Protocol:  3,
			Algorithm: alg,
		}
	}

	cases := []struct {
		name    string
		key     *dns.DNSKEY
		domain  string
		keyType string
		wantErr bool
	}{
		{"valid KSK", mk("example.com.", 257, dns.ED25519), "example.com", "ksk", false},
		{"valid ZSK", mk("example.com.", 256, dns.ECDSAP256SHA256), "example.com", "zsk", false},
		{"case-insensitive owner", mk("EXAMPLE.COM.", 257, dns.ED25519), "example.com", "ksk", false},
		{"ZSK file in KSK slot", mk("example.com.", 256, dns.ED25519), "example.com", "ksk", true},
		{"KSK file in ZSK slot", mk("example.com.", 257, dns.ED25519), "example.com", "zsk", true},
		{"wrong owner", mk("evil.com.", 257, dns.ED25519), "example.com", "ksk", true},
		{"unsupported algorithm (RSA)", mk("example.com.", 257, dns.RSASHA256), "example.com", "ksk", true},
		{"unknown role", mk("example.com.", 257, dns.ED25519), "example.com", "csk", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateLoadedKey(c.key, c.domain, c.keyType)
			if (err != nil) != c.wantErr {
				t.Errorf("validateLoadedKey = %v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}
