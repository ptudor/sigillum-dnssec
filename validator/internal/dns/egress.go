package dns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// EgressPolicy decides which destination addresses the querier may contact
// (RA6X-054). Authoritative-server addresses come from DNS data a client of
// the public service controls (a submitted domain's NS and address records),
// so without a policy a public validator could be steered at loopback,
// link-local or private DNS services reachable only from its own network.
//
// The default policy for the public service is public-only. Classification
// is an explicit globally-reachable policy (RDAYBLUEX-022), not a short
// denylist: an address is public only when it is global unicast in the
// sense of the Go standard library (not unspecified, loopback, multicast or
// link-local), not private (RFC 1918, ULA) and not in any special-purpose
// range of the IANA IPv4/IPv6 registries that is not globally reachable
// (CGNAT, documentation, benchmarking, deprecated site-local, ORCHID, the
// local-use translation prefix, …). Translated and embedded forms are judged
// by what they carry: IPv4-mapped IPv6 as the IPv4 address, 6to4 by its
// embedded IPv4 address, and NAT64/Teredo refused as a whole because their
// reachability cannot be decided from the address. The check runs at the
// one dial boundary every query — UDP and its TCP retry — passes through.
// Trusted destinations (the operator's configured recursive resolver) and
// an explicit allowlist of CIDRs for private diagnostic deployments are
// exempt.
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

// Special-purpose IPv4 ranges that are not globally reachable (IANA IPv4
// Special-Purpose Address Registry, RFC 6890 and successors), beyond what
// netip's IsGlobalUnicast/IsPrivate already exclude.
var reservedV4 = mustPrefixes(
	"0.0.0.0/8",          // "this network"
	"10.0.0.0/8",         // private (RFC 1918)
	"100.64.0.0/10",      // shared address space / CGNAT (RFC 6598)
	"127.0.0.0/8",        // loopback
	"169.254.0.0/16",     // link-local
	"172.16.0.0/12",      // private (RFC 1918)
	"192.0.0.0/24",       // IETF protocol assignments (incl. DS-Lite 192.0.0.0/29)
	"192.0.2.0/24",       // documentation TEST-NET-1
	"192.88.99.0/24",     // deprecated 6to4 relay anycast (RFC 7526)
	"192.168.0.0/16",     // private (RFC 1918)
	"198.18.0.0/15",      // benchmarking (RFC 2544)
	"198.51.100.0/24",    // documentation TEST-NET-2
	"203.0.113.0/24",     // documentation TEST-NET-3
	"224.0.0.0/4",        // multicast
	"240.0.0.0/4",        // reserved (RFC 1112), includes limited broadcast
	"255.255.255.255/32", // limited broadcast
)

// Special-purpose IPv6 ranges that are not globally reachable (IANA IPv6
// Special-Purpose Address Registry), beyond netip's own exclusions.
var reservedV6 = mustPrefixes(
	"::/128",         // unspecified
	"::1/128",        // loopback
	"::ffff:0:0/96",  // IPv4-mapped (judged as IPv4 above; refused if it gets here)
	"64:ff9b::/96",   // NAT64 well-known prefix (reachability undecidable; refused)
	"64:ff9b:1::/48", // local-use IPv4/IPv6 translation (RFC 8215)
	"100::/64",       // discard-only (RFC 6666)
	"2001::/32",      // Teredo (reachability undecidable; refused)
	"2001:2::/48",    // benchmarking (RFC 5180)
	"2001:10::/28",   // ORCHID (deprecated, RFC 4843)
	"2001:20::/28",   // ORCHIDv2 (RFC 7343, not routable)
	"2001:db8::/32",  // documentation
	"3fff::/20",      // documentation (RFC 9637)
	"5f00::/16",      // segment routing SIDs (RFC 9602, not globally reachable)
	"fc00::/7",       // unique local
	"fe80::/10",      // link-local
	"fec0::/10",      // deprecated site-local (RFC 3879)
	"ff00::/8",       // multicast
)

// sixToFourPrefix carries an embedded IPv4 address (RFC 3056) that decides
// the destination's reachability.
var sixToFourPrefix = netip.MustParsePrefix("2002::/16")

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// NonPublic reports whether ip is outside globally reachable unicast space.
// Embedded and translated forms are canonicalized first: an IPv4-mapped IPv6
// address is judged as its IPv4 address and a 6to4 address by the IPv4
// address it embeds. Anything that is not global unicast, is private, or
// falls in a non-globally-reachable special-purpose range is non-public;
// an unparseable address is non-public too.
func NonPublic(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	return nonPublicAddr(addr.Unmap())
}

func nonPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return true
	}
	if addr.Is4() {
		for _, p := range reservedV4 {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	if sixToFourPrefix.Contains(addr) {
		b := addr.As16()
		embedded := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
		return nonPublicAddr(embedded)
	}
	for _, p := range reservedV6 {
		if p.Contains(addr) {
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

// PermitIP is Permit for an already-parsed address (the HTTP dial boundary
// of the RDAP client uses it after resolving a hostname, RDAYBLUEX-020).
func (p *EgressPolicy) PermitIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("egress policy: refusing to dial an unparseable address")
	}
	return p.Permit(ip.String())
}
