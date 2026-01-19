package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ComputeDS computes a DS record from a DNSKEY
func ComputeDS(domain string, dnskey *dns.DNSKEY, digestType uint8) *dns.DS {
	return dnskey.ToDS(digestType)
}

// FormatDSRecords formats DS records for display
func FormatDSRecords(domain string, keyState *KeyState) (string, error) {
	if keyState == nil {
		return "", fmt.Errorf("no key state provided")
	}

	// We need to load the actual DNSKEY to compute the DS
	// For now, generate a placeholder - in the full implementation
	// this would load the key from disk

	var sb strings.Builder

	// Header
	sb.WriteString(fmt.Sprintf(";; DS records for %s\n", domain))
	sb.WriteString(fmt.Sprintf(";; Key Tag: %d, Algorithm: %s\n\n", keyState.ID, keyState.Algorithm))

	// Since we don't have the actual key data here, we provide instructions
	// The actual DS computation happens during signing when we have the key loaded
	sb.WriteString(";; To get the actual DS records, the key must be loaded from disk.\n")
	sb.WriteString(";; Run 'dnssec-tudor sign' first if keys haven't been generated.\n\n")

	// Format for registrar
	sb.WriteString(";; Registrar format:\n")
	sb.WriteString(fmt.Sprintf("Key Tag: %d\n", keyState.ID))
	algNum, err := AlgorithmFromName(keyState.Algorithm)
	if err != nil {
		return "", fmt.Errorf("invalid algorithm in key state: %w", err)
	}
	sb.WriteString(fmt.Sprintf("Algorithm: %d (%s)\n", algNum, keyState.Algorithm))
	sb.WriteString("Digest Type: 2 (SHA-256)\n")
	sb.WriteString("Digest: [computed when keys are loaded]\n")

	return sb.String(), nil
}

// FormatDSRecordsFromKey formats DS records from an actual DNSKEY
func FormatDSRecordsFromKey(domain string, dnskey *dns.DNSKEY) string {
	var sb strings.Builder

	// Compute DS with SHA-256 (digest type 2)
	ds := dnskey.ToDS(dns.SHA256)

	sb.WriteString(fmt.Sprintf(";; DS records for %s\n", domain))
	sb.WriteString(fmt.Sprintf(";; Key Tag: %d, Algorithm: %s\n\n", dnskey.KeyTag(), AlgorithmName(dnskey.Algorithm)))

	// Full DS record
	sb.WriteString(";; Full DS record (digest type 2, SHA-256):\n")
	sb.WriteString(ds.String())
	sb.WriteString("\n\n")

	// Registrar-friendly format
	sb.WriteString(";; Registrar format:\n")
	sb.WriteString(fmt.Sprintf("Key Tag: %d\n", ds.KeyTag))
	sb.WriteString(fmt.Sprintf("Algorithm: %d (%s)\n", ds.Algorithm, AlgorithmName(ds.Algorithm)))
	sb.WriteString(fmt.Sprintf("Digest Type: %d (SHA-256)\n", ds.DigestType))
	sb.WriteString(fmt.Sprintf("Digest: %s\n", strings.ToUpper(ds.Digest)))

	return sb.String()
}

// FormatDNSKEYRecords formats DNSKEY records for display
func FormatDNSKEYRecords(domain string, cfg *Config, ksk, zsk *KeyState) (string, error) {
	if ksk == nil && zsk == nil {
		return "", fmt.Errorf("no keys provided")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(";; DNSKEY records for %s\n\n", domain))

	if ksk != nil {
		sb.WriteString(";; KSK (Key Signing Key):\n")
		sb.WriteString(fmt.Sprintf(";; Key Tag: %d, Algorithm: %s\n", ksk.ID, ksk.Algorithm))
		sb.WriteString(fmt.Sprintf(";; Created: %s, Expires: %s\n", ksk.Created.Format("2006-01-02"), ksk.Expires.Format("2006-01-02")))
		sb.WriteString(";; [Load from key file for full DNSKEY record]\n\n")
	}

	if zsk != nil {
		sb.WriteString(";; ZSK (Zone Signing Key):\n")
		sb.WriteString(fmt.Sprintf(";; Key Tag: %d, Algorithm: %s\n", zsk.ID, zsk.Algorithm))
		sb.WriteString(fmt.Sprintf(";; Created: %s, Expires: %s\n", zsk.Created.Format("2006-01-02"), zsk.Expires.Format("2006-01-02")))
		sb.WriteString(";; [Load from key file for full DNSKEY record]\n")
	}

	return sb.String(), nil
}

// FormatDNSKEYRecordsFromKeys formats DNSKEY records from actual keys
func FormatDNSKEYRecordsFromKeys(domain string, ksk, zsk *dns.DNSKEY) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(";; DNSKEY records for %s\n\n", domain))

	if ksk != nil {
		sb.WriteString(";; KSK (Key Signing Key):\n")
		sb.WriteString(ksk.String())
		sb.WriteString("\n\n")
	}

	if zsk != nil {
		sb.WriteString(";; ZSK (Zone Signing Key):\n")
		sb.WriteString(zsk.String())
		sb.WriteString("\n")
	}

	return sb.String()
}

// HashDNSKEY computes the hash of a DNSKEY for DS record
func HashDNSKEY(domain string, dnskey *dns.DNSKEY) string {
	// Wire format: owner name || DNSKEY RDATA
	// This is handled by miekg/dns's ToDS method, but we can also compute manually

	// For SHA-256 digest
	wire := make([]byte, 256)

	// Add owner name in wire format
	off, _ := dns.PackDomainName(dns.Fqdn(domain), wire, 0, nil, false)
	wire = wire[:off]

	// Add DNSKEY RDATA: flags(2) + protocol(1) + algorithm(1) + public key
	wire = append(wire, byte(dnskey.Flags>>8), byte(dnskey.Flags))
	wire = append(wire, dnskey.Protocol)
	wire = append(wire, dnskey.Algorithm)

	// Decode base64 public key and append
	// (In practice, use dns.ToDS which handles this)

	hash := sha256.Sum256(wire)
	return hex.EncodeToString(hash[:])
}
