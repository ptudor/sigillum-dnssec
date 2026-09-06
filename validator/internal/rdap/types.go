package rdap

// RDAPDomainResponse contains fields we care about from RDAP domain lookup.
// Per RFC 9083, this is a subset of the full RDAP domain object.
type RDAPDomainResponse struct {
	Handle    string     `json:"handle"`
	LDHName   string     `json:"ldhName"`
	SecureDNS *SecureDNS `json:"secureDNS,omitempty"`
}

// SecureDNS represents RDAP secureDNS object (RFC 9083 §5.3).
// This contains DNSSEC delegation information from the registry database.
type SecureDNS struct {
	DelegationSigned bool     `json:"delegationSigned"`
	DSData           []DSData `json:"dsData,omitempty"`
}

// DSData represents a single DS record from RDAP.
// Note: RDAP uses different field names than DNS wire format.
type DSData struct {
	KeyTag     int    `json:"keyTag"`
	Algorithm  int    `json:"algorithm"`
	DigestType int    `json:"digestType"`
	Digest     string `json:"digest"`
}
