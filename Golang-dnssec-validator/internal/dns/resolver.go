package dns

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Resolver handles nameserver and address resolution
type Resolver struct {
	querier   *Querier
	recursive string // Recursive resolver for NS lookups
}

// NewResolver creates a new resolver
func NewResolver(timeout time.Duration, recursiveServer string) *Resolver {
	if recursiveServer == "" {
		recursiveServer = "8.8.8.8" // Default to Google Public DNS
	}
	return &Resolver{
		querier:   NewQuerier(timeout),
		recursive: recursiveServer,
	}
}

// ResolveNS resolves the NS records for a zone using a recursive resolver
func (r *Resolver) ResolveNS(ctx context.Context, zone string) ([]NSRecord, error) {
	// Query NS records from a recursive resolver
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(zone), dns.TypeNS)
	msg.RecursionDesired = true

	client := &dns.Client{
		Net:     "udp",
		Timeout: r.querier.timeout,
	}

	resp, _, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(r.recursive, "53"))
	if err != nil {
		return nil, err
	}

	var nsRecords []NSRecord
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nsRecords = append(nsRecords, NSRecord{
				Name: ns.Ns,
			})
		}
	}

	// If no NS in answer, check authority section (for delegation)
	if len(nsRecords) == 0 {
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsRecords = append(nsRecords, NSRecord{
					Name: ns.Ns,
				})
			}
		}
	}

	return nsRecords, nil
}

// ResolveAddresses resolves both A and AAAA records for a hostname
func (r *Resolver) ResolveAddresses(ctx context.Context, hostname string) ([]net.IP, error) {
	var addresses []net.IP

	// Query A records
	msgA := new(dns.Msg)
	msgA.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	msgA.RecursionDesired = true

	client := &dns.Client{
		Net:     "udp",
		Timeout: r.querier.timeout,
	}

	respA, _, err := client.ExchangeContext(ctx, msgA, net.JoinHostPort(r.recursive, "53"))
	if err == nil && respA.Rcode == dns.RcodeSuccess {
		for _, rr := range respA.Answer {
			if a, ok := rr.(*dns.A); ok {
				addresses = append(addresses, a.A)
			}
		}
	}

	// Query AAAA records
	msgAAAA := new(dns.Msg)
	msgAAAA.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
	msgAAAA.RecursionDesired = true

	respAAAA, _, err := client.ExchangeContext(ctx, msgAAAA, net.JoinHostPort(r.recursive, "53"))
	if err == nil && respAAAA.Rcode == dns.RcodeSuccess {
		for _, rr := range respAAAA.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				addresses = append(addresses, aaaa.AAAA)
			}
		}
	}

	return addresses, nil
}

// ResolveNSWithAddresses resolves NS records and their addresses
func (r *Resolver) ResolveNSWithAddresses(ctx context.Context, zone string) ([]NSRecord, error) {
	nsRecords, err := r.ResolveNS(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Resolve addresses for each NS
	for i := range nsRecords {
		addrs, err := r.ResolveAddresses(ctx, nsRecords[i].Name)
		if err == nil {
			nsRecords[i].Addresses = addrs
		}
	}

	return nsRecords, nil
}

// GetRootServers returns the root server addresses
func GetRootServers() []string {
	// Root server IPv4 addresses (a.root-servers.net through m.root-servers.net)
	return []string{
		"198.41.0.4",     // a.root-servers.net
		"199.9.14.201",   // b.root-servers.net
		"192.33.4.12",    // c.root-servers.net
		"199.7.91.13",    // d.root-servers.net
		"192.203.230.10", // e.root-servers.net
		"192.5.5.241",    // f.root-servers.net
		"192.112.36.4",   // g.root-servers.net
		"198.97.190.53",  // h.root-servers.net
		"192.36.148.17",  // i.root-servers.net
		"192.58.128.30",  // j.root-servers.net
		"193.0.14.129",   // k.root-servers.net
		"199.7.83.42",    // l.root-servers.net
		"202.12.27.33",   // m.root-servers.net
	}
}

// QueryAuthoritative queries an authoritative server directly
func (r *Resolver) QueryAuthoritative(ctx context.Context, server, qname string, qtype uint16) (*QueryResult, error) {
	return r.querier.Query(ctx, server, qname, qtype)
}

// QueryDNSKEYAuthoritative queries DNSKEY from an authoritative server
func (r *Resolver) QueryDNSKEYAuthoritative(ctx context.Context, server, zone string) (*QueryResult, error) {
	return r.querier.QueryDNSKEY(ctx, server, zone)
}

// QueryDSAuthoritative queries DS from an authoritative server
func (r *Resolver) QueryDSAuthoritative(ctx context.Context, server, zone string) (*QueryResult, error) {
	return r.querier.QueryDS(ctx, server, zone)
}

// QueryRecordAuthoritative queries any record type from an authoritative server
func (r *Resolver) QueryRecordAuthoritative(ctx context.Context, server, name string, qtype uint16) (*QueryResult, error) {
	return r.querier.Query(ctx, server, name, qtype)
}

// QueryRecordRecursive queries any record type using the recursive resolver
func (r *Resolver) QueryRecordRecursive(ctx context.Context, name string, qtype uint16) (*QueryResult, error) {
	return r.querier.QueryWithRecursion(ctx, r.recursive, name, qtype, true)
}

// CheckZoneCut checks if a domain is a zone cut (has NS records)
// Returns true if the domain has its own NS records (is a delegation point)
func (r *Resolver) CheckZoneCut(ctx context.Context, domain string) (bool, error) {
	// Query NS records for the domain
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	msg.RecursionDesired = true

	client := &dns.Client{
		Net:     "udp",
		Timeout: r.querier.timeout,
	}

	resp, _, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(r.recursive, "53"))
	if err != nil {
		return false, err
	}

	// Check if we got NS records in the answer section
	// (not just in the authority section which would be a referral)
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.NS); ok {
			return true, nil
		}
	}

	return false, nil
}

// DiscoverZoneCuts discovers actual zone cuts between root and domain
// Returns the list of actual zones in the chain (where NS records exist)
func (r *Resolver) DiscoverZoneCuts(ctx context.Context, domain string) ([]string, error) {
	// Start with root
	zones := []string{"."}

	// Normalize domain
	domain = dns.Fqdn(domain)
	if domain == "." {
		return zones, nil
	}

	// Split into labels
	labels := dns.SplitDomainName(domain)
	if len(labels) == 0 {
		return zones, nil
	}

	// Check each potential zone from TLD down
	// e.g., for www.iana.org: check org., iana.org., www.iana.org.
	for i := len(labels) - 1; i >= 0; i-- {
		candidate := dns.Fqdn(labels[i] + "." + strings.Join(labels[i+1:], "."))
		if i == len(labels)-1 {
			candidate = dns.Fqdn(labels[i])
		}

		isZone, err := r.CheckZoneCut(ctx, candidate)
		if err != nil {
			// On error, assume it might be a zone (fail-safe)
			zones = append(zones, candidate)
			continue
		}

		if isZone {
			zones = append(zones, candidate)
		}
	}

	return zones, nil
}
