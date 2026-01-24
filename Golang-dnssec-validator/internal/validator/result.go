package validator

import (
	"time"

	"github.com/ptudor/dnssec-validator/internal/dns"
)

// ValidationStatus represents the DNSSEC validation state
type ValidationStatus string

const (
	StatusSecure        ValidationStatus = "secure"        // Full chain of trust verified
	StatusInsecure      ValidationStatus = "insecure"      // Zone not signed (no DS in parent)
	StatusBogus         ValidationStatus = "bogus"         // Validation failed
	StatusIndeterminate ValidationStatus = "indeterminate" // Cannot determine (timeout, SERVFAIL)
	StatusValidating    ValidationStatus = "validating"    // Currently being validated
)

// ZoneResult represents the validation result for a single zone
type ZoneResult struct {
	Zone           string             `json:"zone"`
	Status         ValidationStatus   `json:"status"`
	Nameservers    []NameserverResult `json:"nameservers"`
	DNSKEY         []dns.DNSKEYRecord `json:"dnskey,omitempty"`
	DS             []dns.DSRecord     `json:"ds,omitempty"`
	RRSIG          []dns.RRSIGRecord  `json:"rrsig,omitempty"`
	NSEC           []dns.NSECRecord   `json:"nsec,omitempty"`
	NSEC3          []dns.NSEC3Record  `json:"nsec3,omitempty"`
	NSEC3OptOut    bool               `json:"nsec3_opt_out,omitempty"`    // RFC 5155 opt-out flag
	WildcardSource string             `json:"wildcard_source,omitempty"` // RFC 4034 §3.1.3 wildcard detection
	DenialProof      *NSECProof         `json:"denial_proof,omitempty"`      // NSEC/NSEC3 proof of non-existence
	RecordValidation *RecordValidation  `json:"record_validation,omitempty"` // Actual record RRSIG verification
	DSValidation     *DSValidation      `json:"ds_validation,omitempty"`     // DS RRSIG verification from parent
	ChainLink        *ChainLink         `json:"chain_link,omitempty"`
	Disagreements  []Disagreement     `json:"disagreements,omitempty"`
	Warnings       []string           `json:"warnings,omitempty"`
	Errors         []string           `json:"errors,omitempty"`
	QueryTimeNs    int64              `json:"query_time_ns"`
	Timestamp      time.Time          `json:"timestamp"`
}

// NameserverResult represents the result from a single nameserver
type NameserverResult struct {
	Name      string          `json:"name"`
	Addresses []AddressResult `json:"addresses"`
}

// AddressResult represents the result from a single IP address
type AddressResult struct {
	IP       string           `json:"ip"`
	Status   ValidationStatus `json:"status"`
	RTTNs    int64            `json:"rtt_ns"`
	Error    string           `json:"error,omitempty"`
	Response *dns.QueryResult `json:"response,omitempty"`
}

// ChainLink represents the chain of trust link between parent and child zones
type ChainLink struct {
	ParentZone   string            `json:"parent_zone"`
	ChildZone    string            `json:"child_zone"`
	ParentDS     []dns.DSRecord    `json:"parent_ds,omitempty"`
	ChildKSK     *dns.DNSKEYRecord `json:"child_ksk,omitempty"`
	DSMatchesKSK bool              `json:"ds_matches_ksk"`
	Algorithm    string            `json:"algorithm"`
	DigestType   string            `json:"digest_type"`
	KeyTag       uint16            `json:"key_tag"`
}

// ValidationResult represents the complete validation result
type ValidationResult struct {
	Domain      string             `json:"domain"`
	QueryType   string             `json:"query_type"`
	Result      ValidationStatus   `json:"result"`
	Chain       []ZoneResult       `json:"chain"`
	CNAMEChains []CNAMEChainResult `json:"cname_chains,omitempty"` // CNAME targets validated
	DurationMs  int64              `json:"duration_ms"`
	Timestamp   time.Time          `json:"timestamp"`
	Errors      []string           `json:"errors,omitempty"`
	Warnings    []string           `json:"warnings,omitempty"`
}

// CNAMEChainResult represents validation of a CNAME target
type CNAMEChainResult struct {
	Source string           `json:"source"` // The name that has the CNAME
	Target string           `json:"target"` // The CNAME target
	Result ValidationStatus `json:"result"` // Validation result for target's chain
	Chain  []ZoneResult     `json:"chain"`  // The target's zone chain
}

// SSEEvent represents a Server-Sent Event
type SSEEvent struct {
	Type string      `json:"type"` // start, zone, progress, warning, error, complete
	Data interface{} `json:"data"`
}

// StartEvent is sent when validation begins
type StartEvent struct {
	Domain    string    `json:"domain"`
	QueryType string    `json:"query_type,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Mode      string    `json:"mode"` // quick or extended
}

// ZoneEvent is sent for each zone validation result
type ZoneEvent struct {
	Zone       string           `json:"zone"`
	Status     ValidationStatus `json:"status"`
	ZoneResult *ZoneResult      `json:"zone_result,omitempty"`
}

// ProgressEvent is sent during validation to show progress
type ProgressEvent struct {
	Zone   string `json:"zone"`
	Server string `json:"server"`
	IP     string `json:"ip,omitempty"`
	Action string `json:"action"` // querying, validating, etc.
}

// WarningEvent is sent for non-fatal issues
type WarningEvent struct {
	Zone     string `json:"zone"`
	Message  string `json:"message"`
	Severity string `json:"severity"` // low, medium, high
}

// ErrorEvent is sent when an error occurs
type ErrorEvent struct {
	Zone    string `json:"zone,omitempty"`
	Message string `json:"message"`
	Fatal   bool   `json:"fatal"`
}

// CompleteEvent is sent when validation is complete
type CompleteEvent struct {
	Result      ValidationStatus   `json:"result"`
	Chain       []ZoneResult       `json:"chain"`
	CNAMEChains []CNAMEChainResult `json:"cname_chains,omitempty"`
	DurationMs  int64              `json:"duration_ms"`
	Errors      []string           `json:"errors,omitempty"`
	Warnings    []string           `json:"warnings,omitempty"`
}

// CNAMEEvent is sent when a CNAME is detected and being followed
type CNAMEEvent struct {
	Source string `json:"source"` // The name with the CNAME
	Target string `json:"target"` // The CNAME target
}

// Disagreement represents a disagreement between nameservers
type Disagreement struct {
	Server   string `json:"server"`
	IP       string `json:"ip"`
	Issue    string `json:"issue"`
	Expected string `json:"expected"`
	Got      string `json:"got"`
}

// RecordValidation represents validation of an actual record (A, AAAA, MX, etc.)
type RecordValidation struct {
	RecordType     string `json:"record_type"`      // "A", "AAAA", "MX", etc.
	RecordCount    int    `json:"record_count"`     // Number of records found
	RRSIGVerified  bool   `json:"rrsig_verified"`   // RRSIG cryptographically verified
	SigningKeyTag  uint16 `json:"signing_key_tag"`  // Key tag of ZSK that signed
	Error          string `json:"error,omitempty"`
}

// DSValidation represents validation of DS record signature from parent
type DSValidation struct {
	ParentZone       string `json:"parent_zone"`
	DSCount          int    `json:"ds_count"`
	RRSIGVerified    bool   `json:"rrsig_verified"`    // DS RRSIG verified by parent's ZSK
	ParentSigningKey uint16 `json:"parent_signing_key"` // Parent ZSK key tag
	Error            string `json:"error,omitempty"`
}

// NewZoneResult creates a new ZoneResult with initialized fields
func NewZoneResult(zone string) *ZoneResult {
	return &ZoneResult{
		Zone:        zone,
		Status:      StatusValidating,
		Nameservers: make([]NameserverResult, 0),
		Warnings:    make([]string, 0),
		Errors:      make([]string, 0),
		Timestamp:   time.Now(),
	}
}

// AddWarning adds a warning to the zone result
func (z *ZoneResult) AddWarning(msg string) {
	z.Warnings = append(z.Warnings, msg)
}

// AddError adds an error to the zone result
func (z *ZoneResult) AddError(msg string) {
	z.Errors = append(z.Errors, msg)
}

// IsSecure returns true if the zone is secure
func (z *ZoneResult) IsSecure() bool {
	return z.Status == StatusSecure
}

// IsBogus returns true if the zone validation failed
func (z *ZoneResult) IsBogus() bool {
	return z.Status == StatusBogus
}
