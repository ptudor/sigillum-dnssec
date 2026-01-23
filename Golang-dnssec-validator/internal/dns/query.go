package dns

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Querier handles DNS queries
type Querier struct {
	timeout time.Duration
}

// NewQuerier creates a new DNS querier
func NewQuerier(timeout time.Duration) *Querier {
	return &Querier{
		timeout: timeout,
	}
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

	// Create client
	client := &dns.Client{
		Net:     "udp",
		Timeout: q.timeout,
	}

	// Try UDP first
	start := time.Now()
	resp, rtt, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(server, "53"))
	result.RTT = rtt

	// If truncated, retry with TCP
	if err == nil && resp.Truncated {
		result.Truncated = true
		client.Net = "tcp"
		start = time.Now()
		resp, rtt, err = client.ExchangeContext(ctx, msg, net.JoinHostPort(server, "53"))
		result.RTT = rtt
	}

	if err != nil {
		result.Error = err.Error()
		return result, nil // Return result with error, not Go error
	}

	_ = start // Silence unused variable if needed

	result.RCode = resp.Rcode
	result.RCodeName = RCodeName(resp.Rcode)
	result.Authoritative = resp.Authoritative

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
	// Parse all sections: Answer, Ns (Authority), Extra
	allRRs := append(resp.Answer, resp.Ns...)
	allRRs = append(allRRs, resp.Extra...)

	for _, rr := range allRRs {
		switch v := rr.(type) {
		case *dns.DNSKEY:
			dnskey := DNSKEYRecord{
				Flags:     v.Flags,
				Protocol:  v.Protocol,
				Algorithm: v.Algorithm,
				PublicKey: base64.StdEncoding.EncodeToString([]byte(v.PublicKey)),
				KeyTag:    v.KeyTag(),
				IsKSK:     v.Flags&0x0001 == 0x0001, // SEP bit
				IsZSK:     v.Flags&0x0100 == 0x0100, // Zone Key bit
			}
			// KSK has both Zone Key and SEP bits set (257)
			// ZSK has only Zone Key bit set (256)
			dnskey.IsKSK = v.Flags == 257
			dnskey.IsZSK = v.Flags == 256
			result.DNSKEY = append(result.DNSKEY, dnskey)

		case *dns.DS:
			ds := DSRecord{
				KeyTag:     v.KeyTag,
				Algorithm:  v.Algorithm,
				DigestType: v.DigestType,
				Digest:     strings.ToUpper(v.Digest),
			}
			result.DS = append(result.DS, ds)

		case *dns.RRSIG:
			rrsig := RRSIGRecord{
				TypeCovered: v.TypeCovered,
				Algorithm:   v.Algorithm,
				Labels:      v.Labels,
				OriginalTTL: v.OrigTtl,
				Expiration:  time.Unix(int64(v.Expiration), 0),
				Inception:   time.Unix(int64(v.Inception), 0),
				KeyTag:      v.KeyTag,
				SignerName:  v.SignerName,
				Signature:   base64.StdEncoding.EncodeToString([]byte(v.Signature)),
			}
			// Check validity
			now := time.Now()
			rrsig.IsExpired = now.After(rrsig.Expiration)
			rrsig.IsValid = now.After(rrsig.Inception) && now.Before(rrsig.Expiration)
			result.RRSIG = append(result.RRSIG, rrsig)

		case *dns.NSEC:
			nsec := NSECRecord{
				NextDomain: v.NextDomain,
				TypeBitmap: make([]string, 0),
			}
			for _, t := range v.TypeBitMap {
				nsec.TypeBitmap = append(nsec.TypeBitmap, TypeName(t))
			}
			result.NSEC = append(result.NSEC, nsec)

		case *dns.NSEC3:
			nsec3 := NSEC3Record{
				Algorithm:  v.Hash,
				Flags:      v.Flags,
				Iterations: v.Iterations,
				Salt:       strings.ToUpper(v.Salt),
				NextHashed: strings.ToUpper(v.NextDomain),
				TypeBitmap: make([]string, 0),
			}
			for _, t := range v.TypeBitMap {
				nsec3.TypeBitmap = append(nsec3.TypeBitmap, TypeName(t))
			}
			result.NSEC3 = append(result.NSEC3, nsec3)

		case *dns.NS:
			ns := NSRecord{
				Name: v.Ns,
			}
			result.NS = append(result.NS, ns)

		case *dns.CNAME:
			cname := CNAMERecord{
				Name:   v.Hdr.Name,
				Target: v.Target,
			}
			result.CNAME = append(result.CNAME, cname)
		}
	}
}

// QueryWithRetry performs a DNS query with retries
func (q *Querier) QueryWithRetry(ctx context.Context, server, qname string, qtype uint16, retries int) (*QueryResult, error) {
	var lastResult *QueryResult
	var lastErr error

	for i := 0; i <= retries; i++ {
		result, err := q.Query(ctx, server, qname, qtype)
		if err != nil {
			lastErr = err
			continue
		}
		if result.Error == "" && result.RCode == 0 {
			return result, nil
		}
		lastResult = result
	}

	if lastResult != nil {
		return lastResult, nil
	}
	return nil, fmt.Errorf("all retries failed: %v", lastErr)
}
