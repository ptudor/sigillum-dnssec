package dns

import (
	"fmt"
	"net"
	"strings"
)

// EgressPolicy decides which destination addresses the querier may contact
// (RA6X-054). Authoritative-server addresses come from DNS data a client of
// the public service controls (a submitted domain's NS and address records),
// so without a policy a public validator could be steered at loopback,
// link-local or private DNS services reachable only from its own network.
//
// The default policy for the public service is public-only: loopback,
// link-local, private (RFC 1918, ULA, CGNAT), unspecified, multicast and
// reserved destinations are refused, IPv4-mapped IPv6 addresses are judged
// as their IPv4 form, and the check runs at the one dial boundary every
// query — UDP and its TCP retry — passes through. Trusted destinations (the
// operator's configured recursive resolver) and an explicit allowlist of
// CIDRs for private diagnostic deployments are exempt.
type EgressPolicy struct {
	// AllowPrivate disables the non-public check entirely (a deliberately
	// internal deployment).
	AllowPrivate bool
	// Allow lists non-public destinations that are permitted anyway.
	Allow []*net.IPNet
	// Trusted lists exact hosts (IP or name) that are always permitted, such
	// as the configured recursive resolver.
	Trusted map[string]bool
}

// PublicOnlyPolicy returns the default policy: public destinations plus the
// trusted hosts given.
func PublicOnlyPolicy(trusted ...string) *EgressPolicy {
	p := &EgressPolicy{Trusted: map[string]bool{}}
	for _, h := range trusted {
		if h = strings.TrimSpace(h); h != "" {
			p.Trusted[canonicalHost(h)] = true
		}
	}
	return p
}

// ParseEgressAllowlist parses CIDR strings into networks.
func ParseEgressAllowlist(cidrs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("invalid egress allowlist entry %q: %w", c, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// canonicalHost strips a port and brackets and lowercases a host string.
func canonicalHost(server string) string {
	host := server
	if h, _, err := net.SplitHostPort(server); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// reservedV4 are IPv4 ranges that are never public unicast destinations.
var reservedV4 = mustCIDRs(
	"0.0.0.0/8",      // this network
	"10.0.0.0/8",     // private
	"100.64.0.0/10",  // CGNAT
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local
	"172.16.0.0/12",  // private
	"192.0.0.0/24",   // IETF protocol assignments
	"192.168.0.0/16", // private
	"198.18.0.0/15",  // benchmarking
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved, includes broadcast
)

// reservedV6 are IPv6 ranges that are never public unicast destinations.
var reservedV6 = mustCIDRs(
	"::/128",        // unspecified
	"::1/128",       // loopback
	"::ffff:0:0/96", // IPv4-mapped (judged as IPv4 above; refused if it gets here)
	"64:ff9b::/96",  // NAT64 well-known prefix (maps to IPv4; refused conservatively)
	"100::/64",      // discard-only
	"2001:db8::/32", // documentation
	"fc00::/7",      // unique local
	"fe80::/10",     // link-local
	"ff00::/8",      // multicast
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	nets, err := ParseEgressAllowlist(cidrs)
	if err != nil {
		panic(err)
	}
	return nets
}

// NonPublic reports whether ip is outside public unicast space.
func NonPublic(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		for _, n := range reservedV4 {
			if n.Contains(v4) {
				return true
			}
		}
		return false
	}
	for _, n := range reservedV6 {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Permit reports whether the policy allows a query to server (an IP, or
// host:port), with a reason when it does not. A nil policy permits everything.
func (p *EgressPolicy) Permit(server string) error {
	if p == nil {
		return nil
	}
	host := canonicalHost(server)
	if p.Trusted[host] {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("egress policy: refusing to query %q: not an IP address and not a trusted destination", server)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if p.AllowPrivate || !NonPublic(ip) {
		return nil
	}
	for _, n := range p.Allow {
		if n.Contains(ip) {
			return nil
		}
	}
	return fmt.Errorf("egress policy: refusing to query %s: non-public destination (loopback, link-local, private or reserved address); allow it with private_destination_allowlist if this deployment should reach it", ip)
}
