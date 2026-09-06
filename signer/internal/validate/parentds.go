package validate

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
)

// Parent-DS and publication probes that account for EVERY authoritative
// server (RA6X-003, RA6X-004). A rollover decision based on one server's
// answer can race the parent's own propagation; these probes report only
// what all reachable servers agree on.

// resolveAllNS returns the IP:53 address of every nameserver of a zone that
// can be resolved through the configured recursive resolver, IPv4 and IPv6.
func (v *Validator) resolveAllNS(zone string) ([]string, error) {
	resolver := v.resolverAddr()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeNS)
	m.RecursionDesired = true
	c := new(dns.Client)
	c.Timeout = v.timeout
	r, _, err := c.Exchange(m, resolver)
	if err != nil {
		return nil, fmt.Errorf("NS lookup for %s: %w", zone, err)
	}

	var nsNames []string
	for _, rr := range r.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			nsNames = append(nsNames, ns.Ns)
		}
	}
	if len(nsNames) == 0 {
		for _, rr := range r.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsNames = append(nsNames, ns.Ns)
			}
		}
	}
	if len(nsNames) == 0 {
		return nil, fmt.Errorf("no NS records found for %s", zone)
	}

	seen := map[string]bool{}
	var addrs []string
	add := func(ip string) {
		a := net.JoinHostPort(ip, v.portOr())
		if !seen[a] {
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	for _, nsName := range nsNames {
		found := false
		for _, rr := range r.Extra {
			switch addr := rr.(type) {
			case *dns.A:
				if dns.CanonicalName(addr.Hdr.Name) == dns.CanonicalName(nsName) {
					add(addr.A.String())
					found = true
				}
			case *dns.AAAA:
				if dns.CanonicalName(addr.Hdr.Name) == dns.CanonicalName(nsName) {
					add(addr.AAAA.String())
					found = true
				}
			}
		}
		if found {
			continue
		}
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			am := new(dns.Msg)
			am.SetQuestion(dns.Fqdn(nsName), qtype)
			am.RecursionDesired = true
			ar, _, err := c.Exchange(am, resolver)
			if err != nil {
				continue
			}
			for _, rr := range ar.Answer {
				switch addr := rr.(type) {
				case *dns.A:
					add(addr.A.String())
				case *dns.AAAA:
					add(addr.AAAA.String())
				}
			}
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("could not resolve any NS for %s to an IP address", zone)
	}
	sort.Strings(addrs)
	return addrs, nil
}

// ProbeParentDS queries every authoritative server of the parent zone for the
// DS RRset of domain and reports, per KSK, whether its DS (any supported
// digest) is present on all of them or absent from all of them, plus the
// largest DS TTL seen. A server that cannot be queried makes the probe fail:
// a decision must not be taken on a partial view.
func (v *Validator) ProbeParentDS(domain string, ksks []*dns.DNSKEY) (signerpkg.ParentDSObservation, error) {
	obs := signerpkg.ParentDSObservation{PresentOnAll: map[uint16]bool{}, AbsentOnAll: map[uint16]bool{}}
	parents, err := v.resolveAllNS(findParentZone(domain))
	if err != nil {
		return obs, err
	}
	expected := map[uint16][]*dns.DS{}
	for _, k := range ksks {
		if k == nil {
			continue
		}
		for _, dt := range []uint8{dns.SHA256, dns.SHA384} {
			if ds := k.ToDS(dt); ds != nil {
				expected[k.KeyTag()] = append(expected[k.KeyTag()], ds)
			}
		}
	}
	presentCount := map[uint16]int{}
	for _, server := range parents {
		msg, err := queryDirect(server, dns.Fqdn(domain), dns.TypeDS, v.timeout)
		if err != nil {
			return obs, fmt.Errorf("DS query to parent server %s failed: %w", server, err)
		}
		obs.Servers = append(obs.Servers, server)
		for _, rr := range msg.Answer {
			ds, ok := rr.(*dns.DS)
			if !ok {
				continue
			}
			if ds.Hdr.Ttl > obs.TTL {
				obs.TTL = ds.Hdr.Ttl
			}
		}
		for tag, exps := range expected {
			matched := false
			for _, rr := range msg.Answer {
				ds, ok := rr.(*dns.DS)
				if !ok {
					continue
				}
				for _, exp := range exps {
					if ds.KeyTag == exp.KeyTag && ds.Algorithm == exp.Algorithm && ds.DigestType == exp.DigestType && strings.EqualFold(ds.Digest, exp.Digest) {
						matched = true
					}
				}
			}
			if matched {
				presentCount[tag]++
			}
		}
	}
	for tag := range expected {
		obs.PresentOnAll[tag] = presentCount[tag] == len(parents)
		obs.AbsentOnAll[tag] = presentCount[tag] == 0
	}
	return obs, nil
}

// ProbePublishedSerial reports whether every authoritative server of the zone
// serves the SOA with the given serial (publication confirmation for
// dnssec.publication = "probe", RA6X-004). Any server that cannot be queried
// or serves another serial means "not yet".
func (v *Validator) ProbePublishedSerial(domain string, serial uint32) (bool, string, error) {
	servers, err := v.resolveAllNS(dns.Fqdn(domain))
	if err != nil {
		return false, "", err
	}
	for _, server := range servers {
		msg, err := queryDirect(server, dns.Fqdn(domain), dns.TypeSOA, v.timeout)
		if err != nil {
			return false, fmt.Sprintf("SOA query to %s failed: %v", server, err), nil
		}
		served := uint32(0)
		found := false
		for _, rr := range msg.Answer {
			if soa, ok := rr.(*dns.SOA); ok {
				served, found = soa.Serial, true
			}
		}
		if !found {
			return false, fmt.Sprintf("%s returned no SOA", server), nil
		}
		if served != serial {
			return false, fmt.Sprintf("%s serves serial %d, published %d", server, served, serial), nil
		}
	}
	return true, fmt.Sprintf("serial %d served by %d server(s)", serial, len(servers)), nil
}
