package dns

import (
	"context"
	"fmt"
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
		recursiveServer = "127.0.0.1" // Default to the local recursive resolver (loopback); never a public/ad DNS
	}
	return &Resolver{
		querier:   NewQuerier(timeout),
		recursive: recursiveServer,
	}
}

// SetDefaultPort changes the port dialled for servers named without one (the
// default is 53) for both authoritative and recursive queries. It exists so a
// hermetic DNS fixture listening on an ephemeral loopback port can stand in
// for the recursive resolver and the authoritative servers it names, driving
// the real resolution and validation code paths (RA6X-050).
// SetEgressPolicy installs the destination policy for every query this
// resolver sends (RA6X-054). The configured recursive resolver is always
// trusted by the policies the service builds.
func (r *Resolver) SetEgressPolicy(p *EgressPolicy) {
	r.querier.SetEgressPolicy(p)
}

// RecursiveServer returns the configured recursive resolver address.
func (r *Resolver) RecursiveServer() string { return r.recursive }

func (r *Resolver) SetDefaultPort(port string) {
	r.querier.port = port
}

// maxAliasHops bounds CNAME following inside one recursive answer when
// collecting a nameserver host's addresses.
const maxAliasHops = 8

// exchangeRecursive sends an infrastructure query to the configured recursive
// resolver over the shared transport: UDP first, retried over TCP when the
// answer is truncated (RA6X-019), with EDNS0 so large NS/address sets fit.
//
// The CD (checking-disabled) bit is always set. These lookups are infrastructure
// queries — "which nameservers serve this zone, and at what addresses" — whose
// answers this tool then validates itself, from the root down, against the
// authoritative servers. A validating recursive resolver (junia points at a
// local unbound) SERVFAILs any name in a DNSSEC-broken zone, which would leave
// the chain stuck at "no nameserver addresses found" and reported as
// indeterminate. Diagnosing exactly those broken zones is the point of this
// tool, so it must ask for the raw data and judge for itself; suppressing the
// resolver's verdict costs nothing, because no trust is ever derived from it.
func (r *Resolver) exchangeRecursive(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qtype)
	msg.RecursionDesired = true
	msg.CheckingDisabled = true
	msg.SetEdns0(4096, false)

	resp, _, _, err := r.querier.exchange(ctx, r.recursive, msg)
	if err != nil {
		return nil, fmt.Errorf("%s %s lookup at %s: %w", qname, TypeName(qtype), r.recursive, err)
	}
	return resp, nil
}

// recordsOwnedBy returns the records of rrtype in rrs owned by owner.
func recordsOwnedBy(rrs []dns.RR, owner string, rrtype uint16) []dns.RR {
	want := dns.CanonicalName(owner)
	out := make([]dns.RR, 0)
	for _, rr := range rrs {
		if rr.Header().Rrtype == rrtype && dns.CanonicalName(rr.Header().Name) == want {
			out = append(out, rr)
		}
	}
	return out
}

// ResolveNS resolves the NS records for a zone using a recursive resolver.
//
// Only NS records owned by the requested zone are accepted (RA6X-019): an NS
// RRset reached through an alias or owned by another name says nothing about
// this zone. Records in the Answer section are preferred; a delegation
// returned in the Authority section for the same owner is accepted when the
// Answer holds none. A non-success RCODE other than NXDOMAIN is an error, and
// NXDOMAIN yields no nameservers.
func (r *Resolver) ResolveNS(ctx context.Context, zone string) ([]NSRecord, error) {
	resp, err := r.exchangeRecursive(ctx, zone, dns.TypeNS)
	if err != nil {
		return nil, err
	}
	switch resp.Rcode {
	case dns.RcodeSuccess:
	case dns.RcodeNameError:
		return nil, nil // the zone does not exist
	default:
		return nil, fmt.Errorf("%s NS lookup: recursive resolver answered %s", zone, RCodeName(resp.Rcode))
	}

	var nsRecords []NSRecord
	for _, rr := range recordsOwnedBy(resp.Answer, zone, dns.TypeNS) {
		nsRecords = append(nsRecords, NSFromRR(rr.(*dns.NS), SectionAnswer))
	}
	if len(nsRecords) == 0 {
		for _, rr := range recordsOwnedBy(resp.Ns, zone, dns.TypeNS) {
			nsRecords = append(nsRecords, NSFromRR(rr.(*dns.NS), SectionAuthority))
		}
	}
	return nsRecords, nil
}

// answerAddresses collects the A or AAAA records that answer host in msg,
// following CNAMEs inside the Answer section from host (bounded), since a
// nameserver host that is an alias is answered with the target's addresses.
func answerAddresses(msg *dns.Msg, host string, rrtype uint16) []net.IP {
	owner := dns.CanonicalName(host)
	for hop := 0; hop < maxAliasHops; hop++ {
		next := ""
		for _, rr := range msg.Answer {
			if c, ok := rr.(*dns.CNAME); ok && dns.CanonicalName(c.Hdr.Name) == owner {
				next = dns.CanonicalName(c.Target)
				break
			}
		}
		if next == "" || next == owner {
			break
		}
		owner = next
	}
	var addrs []net.IP
	for _, rr := range recordsOwnedBy(msg.Answer, owner, rrtype) {
		switch v := rr.(type) {
		case *dns.A:
			addrs = append(addrs, v.A)
		case *dns.AAAA:
			addrs = append(addrs, v.AAAA)
		}
	}
	return addrs
}

// ResolveAddressesDetailed resolves both A and AAAA records for a hostname.
// A family that fails (transport error or a non-success RCODE other than
// NXDOMAIN) is reported in problems while the other family's addresses are
// still returned; err is set only when no family succeeded (RA6X-019). An
// empty NOERROR or NXDOMAIN answer for a family is simply no address.
func (r *Resolver) ResolveAddressesDetailed(ctx context.Context, hostname string) (addresses []net.IP, problems []string, err error) {
	families := []struct {
		name  string
		qtype uint16
	}{{"A", dns.TypeA}, {"AAAA", dns.TypeAAAA}}

	failed := 0
	for _, fam := range families {
		resp, ferr := r.exchangeRecursive(ctx, hostname, fam.qtype)
		if ferr != nil {
			problems = append(problems, fmt.Sprintf("%s lookup failed: %v", fam.name, ferr))
			failed++
			continue
		}
		switch resp.Rcode {
		case dns.RcodeSuccess:
			addresses = append(addresses, answerAddresses(resp, hostname, fam.qtype)...)
		case dns.RcodeNameError:
			// The host does not exist: no addresses in either family.
		default:
			problems = append(problems, fmt.Sprintf("%s lookup: recursive resolver answered %s", fam.name, RCodeName(resp.Rcode)))
			failed++
		}
	}
	if failed == len(families) {
		return nil, problems, fmt.Errorf("address lookup for %s failed: %s", hostname, strings.Join(problems, "; "))
	}
	return addresses, problems, nil
}

// ResolveAddresses resolves both A and AAAA records for a hostname. It fails
// only when neither family could be looked up.
func (r *Resolver) ResolveAddresses(ctx context.Context, hostname string) ([]net.IP, error) {
	addrs, _, err := r.ResolveAddressesDetailed(ctx, hostname)
	return addrs, err
}

// ResolveNSWithAddresses resolves NS records and their addresses. Per-host
// lookup problems are carried on each NSRecord so callers can surface them.
func (r *Resolver) ResolveNSWithAddresses(ctx context.Context, zone string) ([]NSRecord, error) {
	nsRecords, err := r.ResolveNS(ctx, zone)
	if err != nil {
		return nil, err
	}

	// Resolve addresses for each NS
	for i := range nsRecords {
		addrs, problems, err := r.ResolveAddressesDetailed(ctx, nsRecords[i].Name)
		nsRecords[i].Addresses = addrs
		nsRecords[i].LookupErrors = problems
		if err != nil && len(problems) == 0 {
			nsRecords[i].LookupErrors = []string{err.Error()}
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
// Returns true if the domain has its own NS records (is a delegation point).
// Only an NS RRset owned by the domain itself counts (RA6X-019); NS records
// reached through an alias or in the Authority section are a referral to, or
// the apex of, some other zone.
func (r *Resolver) CheckZoneCut(ctx context.Context, domain string) (bool, error) {
	resp, err := r.exchangeRecursive(ctx, domain, dns.TypeNS)
	if err != nil {
		return false, err
	}

	// A SERVFAIL still reaches us for reasons unrelated to DNSSEC (lame delegation,
	// upstream failure); CD only suppresses the resolver's own validation verdict.
	// The zone may well EXIST but be broken, so treat it as a zone cut and let the
	// chain walk report the real error rather than stopping here.
	if resp.Rcode == dns.RcodeServerFailure {
		return true, nil
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false, nil
	}

	return len(recordsOwnedBy(resp.Answer, domain, dns.TypeNS)) > 0, nil
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
			// A cancelled or expired context is not a zone-cut observation; stop
			// so the caller reports the interruption rather than a guessed chain.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
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
