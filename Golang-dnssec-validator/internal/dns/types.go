package dns

import (
	"net"
	"time"
)

// Note: ValidationStatus is defined in internal/validator/result.go
// Do not duplicate it here to avoid import cycles.

// DNSKEYRecord represents a DNSKEY record
type DNSKEYRecord struct {
	Flags     uint16 `json:"flags"`      // 256=ZSK, 257=KSK
	Protocol  uint8  `json:"protocol"`   // Always 3
	Algorithm uint8  `json:"algorithm"`  // 8, 13, 15, etc.
	PublicKey string `json:"public_key"` // Base64
	KeyTag    uint16 `json:"key_tag"`    // Computed identifier
	IsKSK     bool   `json:"is_ksk"`
	IsZSK     bool   `json:"is_zsk"`
	IsRevoked bool   `json:"is_revoked,omitempty"` // RFC 5011 REVOKE bit set
}

// DSRecord represents a DS record
type DSRecord struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"` // 2=SHA-256, 4=SHA-384
	Digest     string `json:"digest"`      // Hex
}

// RRSIGRecord represents an RRSIG record
type RRSIGRecord struct {
	TypeCovered uint16    `json:"type_covered"`
	Algorithm   uint8     `json:"algorithm"`
	Labels      uint8     `json:"labels"`
	OriginalTTL uint32    `json:"original_ttl"`
	Expiration  time.Time `json:"expiration"`
	Inception   time.Time `json:"inception"`
	KeyTag      uint16    `json:"key_tag"`
	SignerName  string    `json:"signer_name"`
	Signature   string    `json:"signature"` // Base64
	IsValid     bool      `json:"is_valid"`
	IsExpired   bool      `json:"is_expired"`
}

// NSECRecord represents an NSEC record
type NSECRecord struct {
	Owner      string   `json:"owner"` // Owner name (from RR header)
	NextDomain string   `json:"next_domain"`
	TypeBitmap []string `json:"type_bitmap"` // Type names covered
}

// NSEC3Record represents an NSEC3 record
type NSEC3Record struct {
	Owner       string   `json:"owner"`        // Full owner name (hashed.zone.)
	HashedOwner string   `json:"hashed_owner"` // Just the hashed portion (base32)
	Algorithm   uint8    `json:"algorithm"`
	Flags       uint8    `json:"flags"`
	Iterations  uint16   `json:"iterations"`
	Salt        string   `json:"salt"` // Hex
	NextHashed  string   `json:"next_hashed"`
	TypeBitmap  []string `json:"type_bitmap"`
}

// NSRecord represents a nameserver record
type NSRecord struct {
	Name      string   `json:"name"`
	Addresses []net.IP `json:"addresses,omitempty"`
}

// CNAMERecord represents a CNAME record
type CNAMERecord struct {
	Name   string `json:"name"`   // The alias name
	Target string `json:"target"` // The canonical name
}

// QueryResult represents the result of a DNS query
type QueryResult struct {
	Server        string         `json:"server"`
	IP            string         `json:"ip"`
	RTT           time.Duration  `json:"rtt_ns"`
	Truncated     bool           `json:"truncated,omitempty"`
	Authoritative bool           `json:"authoritative,omitempty"`
	RCode         int            `json:"rcode"`
	RCodeName     string         `json:"rcode_name"`
	Error         string         `json:"error,omitempty"`
	DNSKEY        []DNSKEYRecord `json:"dnskey,omitempty"`
	DS            []DSRecord     `json:"ds,omitempty"`
	RRSIG         []RRSIGRecord  `json:"rrsig,omitempty"`
	NSEC          []NSECRecord   `json:"nsec,omitempty"`
	NSEC3         []NSEC3Record  `json:"nsec3,omitempty"`
	NS            []NSRecord     `json:"ns,omitempty"`
	CNAME         []CNAMERecord  `json:"cname,omitempty"`
	RawResponse   []byte         `json:"raw_response,omitempty"`
}

// RootAnchors represents the root trust anchor file structure
type RootAnchors struct {
	Source      string   `json:"source"` // Original data source (e.g., IANA XML URL)
	Zone        string   `json:"zone"`
	GeneratedAt string   `json:"generatedAt"`
	Anchors     []Anchor `json:"anchors"`
	LoadedFrom  string   `json:"loadedFrom,omitempty"` // Where validator loaded from (file path or URL)
}

// Anchor represents a single trust anchor
type Anchor struct {
	ID             string  `json:"id"`
	KeyTag         int     `json:"keyTag"`
	Algorithm      int     `json:"algorithm"`
	AlgorithmName  string  `json:"algorithmName"`
	DigestType     int     `json:"digestType"`
	DigestTypeName string  `json:"digestTypeName"`
	Digest         string  `json:"digest"`
	ValidFrom      string  `json:"validFrom"`
	ValidUntil     *string `json:"validUntil"`
	PublicKey      string  `json:"publicKey,omitempty"`
	Flags          int     `json:"flags,omitempty"`
}

// AlgorithmName returns the human-readable algorithm name
func AlgorithmName(alg uint8) string {
	names := map[uint8]string{
		5:  "RSASHA1",
		7:  "RSASHA1-NSEC3-SHA1",
		8:  "RSASHA256",
		10: "RSASHA512",
		13: "ECDSAP256SHA256",
		14: "ECDSAP384SHA384",
		15: "ED25519",
		16: "ED448",
	}
	if name, ok := names[alg]; ok {
		return name
	}
	return "UNKNOWN"
}

// DigestTypeName returns the human-readable digest type name
func DigestTypeName(dt uint8) string {
	names := map[uint8]string{
		1: "SHA-1",
		2: "SHA-256",
		4: "SHA-384",
	}
	if name, ok := names[dt]; ok {
		return name
	}
	return "UNKNOWN"
}

// RCodeName returns the human-readable RCODE name
func RCodeName(rcode int) string {
	names := map[int]string{
		0: "NOERROR",
		1: "FORMERR",
		2: "SERVFAIL",
		3: "NXDOMAIN",
		4: "NOTIMP",
		5: "REFUSED",
	}
	if name, ok := names[rcode]; ok {
		return name
	}
	return "UNKNOWN"
}

// TypeName returns the human-readable RR type name
func TypeName(t uint16) string {
	names := map[uint16]string{
		1:   "A",
		2:   "NS",
		5:   "CNAME",
		6:   "SOA",
		15:  "MX",
		16:  "TXT",
		28:  "AAAA",
		43:  "DS",
		46:  "RRSIG",
		47:  "NSEC",
		48:  "DNSKEY",
		50:  "NSEC3",
		51:  "NSEC3PARAM",
		257: "CAA",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return "UNKNOWN"
}
