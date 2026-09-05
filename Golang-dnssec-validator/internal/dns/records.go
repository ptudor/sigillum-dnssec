package dns

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Message-section identifiers carried on every parsed record. The validator
// merges the three sections into per-type slices for display, so each record
// must remember where it came from: only Answer-section data can be a positive
// answer, denial records belong in Authority, and nothing in Additional is
// ever promoted to authenticated data (RA6X-007).
const (
	SectionAnswer     = "answer"
	SectionAuthority  = "authority"
	SectionAdditional = "additional"
)

// DNSKEYFromRR converts a wire DNSKEY into the validator's record type,
// preserving its owner, class and message section.
func DNSKEYFromRR(v *dns.DNSKEY, section string) DNSKEYRecord {
	// RFC 4034 §2.1.1 DNSKEY flags, classified by BIT rather than exact
	// equality so a key carrying the REVOKE bit (RFC 5011) or any extra
	// flag is still recognized (R-095):
	//   Zone Key  (0x0100 = 256): the key signs zone data
	//   SEP       (0x0001 =   1): Secure Entry Point (conventionally the KSK)
	//   REVOKE    (0x0080 = 128): RFC 5011 revoked
	// KSK = Zone Key + SEP; ZSK = Zone Key without SEP.
	isZoneKey := v.Flags&0x0100 != 0
	isSEP := v.Flags&0x0001 != 0
	return DNSKEYRecord{
		Owner:     v.Hdr.Name,
		Class:     v.Hdr.Class,
		Section:   section,
		Flags:     v.Flags,
		Protocol:  v.Protocol,
		Algorithm: v.Algorithm,
		PublicKey: v.PublicKey, // miekg/dns already provides base64
		KeyTag:    v.KeyTag(),
		IsKSK:     isZoneKey && isSEP,
		IsZSK:     isZoneKey && !isSEP,
		IsRevoked: v.Flags&0x0080 != 0,
	}
}

// DSFromRR converts a wire DS into the validator's record type.
func DSFromRR(v *dns.DS, section string) DSRecord {
	return DSRecord{
		Owner:      v.Hdr.Name,
		Class:      v.Hdr.Class,
		Section:    section,
		KeyTag:     v.KeyTag,
		Algorithm:  v.Algorithm,
		DigestType: v.DigestType,
		Digest:     strings.ToUpper(v.Digest),
	}
}

// RRSIGFromRR converts a wire RRSIG into the validator's record type. The
// IsValid/IsExpired flags are evaluated against now.
func RRSIGFromRR(v *dns.RRSIG, section string, now time.Time) RRSIGRecord {
	rrsig := RRSIGRecord{
		Owner:       v.Hdr.Name,
		Class:       v.Hdr.Class,
		Section:     section,
		TypeCovered: v.TypeCovered,
		Algorithm:   v.Algorithm,
		Labels:      v.Labels,
		OriginalTTL: v.OrigTtl,
		Expiration:  time.Unix(int64(v.Expiration), 0),
		Inception:   time.Unix(int64(v.Inception), 0),
		KeyTag:      v.KeyTag,
		SignerName:  v.SignerName,
		Signature:   v.Signature, // miekg/dns already provides base64
	}
	rrsig.IsExpired = now.After(rrsig.Expiration)
	rrsig.IsValid = now.After(rrsig.Inception) && now.Before(rrsig.Expiration)
	return rrsig
}

// NSECFromRR converts a wire NSEC into the validator's record type.
func NSECFromRR(v *dns.NSEC, section string) NSECRecord {
	nsec := NSECRecord{
		Owner:      v.Hdr.Name,
		Class:      v.Hdr.Class,
		Section:    section,
		NextDomain: v.NextDomain,
		TypeBitmap: make([]string, 0, len(v.TypeBitMap)),
	}
	for _, t := range v.TypeBitMap {
		nsec.TypeBitmap = append(nsec.TypeBitmap, TypeName(t))
	}
	return nsec
}

// NSEC3FromRR converts a wire NSEC3 into the validator's record type.
func NSEC3FromRR(v *dns.NSEC3, section string) NSEC3Record {
	// Extract hashed owner (first label before zone)
	hashedOwner := ""
	if idx := strings.Index(v.Hdr.Name, "."); idx > 0 {
		hashedOwner = strings.ToUpper(v.Hdr.Name[:idx])
	}
	nsec3 := NSEC3Record{
		Owner:       v.Hdr.Name,
		Class:       v.Hdr.Class,
		Section:     section,
		HashedOwner: hashedOwner,
		Algorithm:   v.Hash,
		Flags:       v.Flags,
		Iterations:  v.Iterations,
		Salt:        strings.ToUpper(v.Salt),
		NextHashed:  strings.ToUpper(v.NextDomain),
		TypeBitmap:  make([]string, 0, len(v.TypeBitMap)),
	}
	for _, t := range v.TypeBitMap {
		nsec3.TypeBitmap = append(nsec3.TypeBitmap, TypeName(t))
	}
	return nsec3
}

// NSFromRR converts a wire NS into the validator's record type.
func NSFromRR(v *dns.NS, section string) NSRecord {
	return NSRecord{
		Owner:   v.Hdr.Name,
		Class:   v.Hdr.Class,
		Section: section,
		Name:    v.Ns,
	}
}

// CNAMEFromRR converts a wire CNAME into the validator's record type.
func CNAMEFromRR(v *dns.CNAME, section string) CNAMERecord {
	return CNAMERecord{
		Name:    v.Hdr.Name,
		Class:   v.Hdr.Class,
		Section: section,
		Target:  v.Target,
	}
}

// InSection reports whether a record's recorded section is one of the given
// sections. A record whose section is unknown (constructed in-process rather
// than parsed from a message) is treated as if it were in the first listed
// section, so callers that build records directly keep working; a parsed
// record always carries its real section.
func InSection(section string, allowed ...string) bool {
	if section == "" {
		return len(allowed) > 0
	}
	for _, a := range allowed {
		if section == a {
			return true
		}
	}
	return false
}
