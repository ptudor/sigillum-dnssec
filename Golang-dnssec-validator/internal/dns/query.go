package dns

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Querier handles DNS queries
type Querier struct {
	timeout time.Duration
	// port is the port dialled for a server named without one (default 53).
	// It exists so a hermetic authoritative fixture on an ephemeral port can be
	// driven through the real query/validation path (RA6X-050).
	port string
}

// NewQuerier creates a new DNS querier
func NewQuerier(timeout time.Duration) *Querier {
	return &Querier{
		timeout: timeout,
		port:    "53",
	}
}

// dial returns the address to dial for a DNS server. Servers are normally
// named without a port ("198.41.0.4", "::1") and get the querier's default
// port (53); an address that already carries a port is passed through, which
// keeps a resolver on a non-standard port working instead of silently
// dialling "host:port:53".
func (q *Querier) dial(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	port := q.port
	if port == "" {
		port = "53"
	}
	return net.JoinHostPort(server, port)
}

// exchange is the shared transport for every query this package sends: UDP
// first, retried over TCP when the UDP answer is truncated, so a large answer
// is never silently treated as complete (RA6X-019). truncated reports that the
// UDP answer was truncated (the returned message is then the TCP answer).
func (q *Querier) exchange(ctx context.Context, server string, msg *dns.Msg) (resp *dns.Msg, rtt time.Duration, truncated bool, err error) {
	client := &dns.Client{
		Net:     "udp",
		Timeout: q.timeout,
	}
	resp, rtt, err = client.ExchangeContext(ctx, msg, q.dial(server))
	if err == nil && resp.Truncated {
		truncated = true
		client.Net = "tcp"
		resp, rtt, err = client.ExchangeContext(ctx, msg, q.dial(server))
	}
	return resp, rtt, truncated, err
}

// Query performs a DNS query to the specified server
func (q *Querier) Query(ctx context.Context, server, qname string, qtype uint16) (*QueryResult, error) {
	return q.QueryWithRecursion(ctx, server, qname, qtype, false)
}

// QueryWithRecursion performs a DNS query with specified recursion setting
func (q *Querier) QueryWithRecursion(ctx context.Context, server, qname string, qtype uint16, recurse bool) (*QueryResult, error) {
	result := &QueryResult{
		Server: server,
		IP:     server,
	}

	// Build the query message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qtype)
	msg.SetEdns0(4096, true) // Enable DNSSEC OK (DO) bit
	msg.RecursionDesired = recurse
	// Recursive queries go to a resolver that may validate and would then answer
	// SERVFAIL for a DNSSEC-broken zone, hiding the very records this tool exists
	// to diagnose. Ask it not to judge; we validate the returned records ourselves.
	// Authoritative queries (recurse=false) ignore CD, so scope it to recursion.
	msg.CheckingDisabled = recurse

	resp, rtt, truncated, err := q.exchange(ctx, server, msg)
	result.RTT = rtt
	result.Truncated = truncated

	if err != nil {
		result.Error = err.Error()
		return result, nil // Return result with error, not Go error
	}

	result.RCode = resp.Rcode
	result.RCodeName = RCodeName(resp.Rcode)
	result.Authoritative = resp.Authoritative

	// Preserve raw response for downstream cryptographic RRset verification.
	if raw, packErr := resp.Pack(); packErr == nil {
		result.RawResponse = raw
	}

	// Parse the response
	q.parseResponse(resp, result)

	return result, nil
}

// QueryDNSKEY queries for DNSKEY records at a zone
func (q *Querier) QueryDNSKEY(ctx context.Context, server, zone string) (*QueryResult, error) {
	return q.Query(ctx, server, zone, dns.TypeDNSKEY)
}

// QueryDS queries for DS records at a zone
func (q *Querier) QueryDS(ctx context.Context, server, zone string) (*QueryResult, error) {
	return q.Query(ctx, server, zone, dns.TypeDS)
}

// QueryNS queries for NS records at a zone
func (q *Querier) QueryNS(ctx context.Context, server, zone string) (*QueryResult, error) {
	return q.Query(ctx, server, zone, dns.TypeNS)
}

// parseResponse extracts DNSSEC records from a DNS response
func (q *Querier) parseResponse(resp *dns.Msg, result *QueryResult) {
	// Record the distinct RR types present in the ANSWER section before the
	// sections are merged below.
	seenAnswerTypes := make(map[uint16]bool)
	for _, rr := range resp.Answer {
		t := rr.Header().Rrtype
		if !seenAnswerTypes[t] {
			seenAnswerTypes[t] = true
			result.AnswerTypes = append(result.AnswerTypes, t)
		}
	}

	// Parse all sections: Answer, Ns (Authority), Extra. Each record keeps its
	// owner, class and section (RA6X-007) so consumers can tell positive
	// Answer data from Authority denial records and never promote anything
	// from Additional to authenticated data.
	now := time.Now()
	q.parseSection(resp.Answer, SectionAnswer, now, result)
	q.parseSection(resp.Ns, SectionAuthority, now, result)
	q.parseSection(resp.Extra, SectionAdditional, now, result)
}

// parseSection converts one message section's DNSSEC-relevant records into the
// per-type display slices on result, tagging each with its section.
func (q *Querier) parseSection(rrs []dns.RR, section string, now time.Time, result *QueryResult) {
	for _, rr := range rrs {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			result.DNSKEY = append(result.DNSKEY, DNSKEYFromRR(v, section))
		case *dns.DS:
			result.DS = append(result.DS, DSFromRR(v, section))
		case *dns.RRSIG:
			result.RRSIG = append(result.RRSIG, RRSIGFromRR(v, section, now))
		case *dns.NSEC:
			result.NSEC = append(result.NSEC, NSECFromRR(v, section))
		case *dns.NSEC3:
			result.NSEC3 = append(result.NSEC3, NSEC3FromRR(v, section))
		case *dns.NS:
			result.NS = append(result.NS, NSFromRR(v, section))
		case *dns.CNAME:
			result.CNAME = append(result.CNAME, CNAMEFromRR(v, section))
		case *dns.DNAME:
			result.DNAME = append(result.DNAME, DNAMEFromRR(v, section))
		}
	}
}
