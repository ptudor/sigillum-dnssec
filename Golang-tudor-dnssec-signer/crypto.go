package main

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// ComputeDS computes a DS record from a DNSKEY
func ComputeDS(domain string, dnskey *dns.DNSKEY, digestType uint8) *dns.DS {
	return dnskey.ToDS(digestType)
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

