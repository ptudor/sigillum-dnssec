package validate

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
)

// Parent-DS and publication probes that account for EVERY authoritative
// server (RA6X-003, RA6X-004). A rollover decision based on one server's
// answer can race the parent's own propagation; these probes report only
// what all reachable servers agree on.
//
// Discovery is by nameserver identity, not by a flat address list
// (RDAYBLUEX-003): every delegated NS name must resolve to at least one
// address, both address families are established for every name, glue is
// accepted only when it is in-bailiwick and owner-matched, truncated
// responses are retried over TCP, and every response must echo the question
// it answers. A delegation that cannot be covered completely is an error, so
// no safety gate advances on a partial view.

// nsTarget is one delegated nameserver identity with the addresses it
// resolved to (host:port, deduplicated, sorted).
type nsTarget struct {
	name  string
	addrs []string
}

// checkQuestion verifies that a response echoes exactly the question asked.
// (The client library already rejects a mismatched message ID.)
func checkQuestion(r, m *dns.Msg) error {
	if len(r.Question) != 1 {
		return fmt.Errorf("response carries %d questions, want exactly the one asked", len(r.Question))
	}
	q, want := r.Question[0], m.Question[0]
	if !strings.EqualFold(dns.Fqdn(q.Name), dns.Fqdn(want.Name)) || q.Qtype != want.Qtype || q.Qclass != want.Qclass {
		return fmt.Errorf("response answers %s/%s, not the query %s/%s",
			q.Name, dns.TypeToString[q.Qtype], want.Name, dns.TypeToString[want.Qtype])
	}
	return nil
}

// exchangeTC performs one exchange, retrying over TCP when the answer is
// truncated, and validates that the response echoes the question.
func exchangeTC(c *dns.Client, m *dns.Msg, server string) (*dns.Msg, error) {
	r, _, err := c.Exchange(m, server)
	if err != nil {
		return nil, err
	}
	if r.Truncated {
		tc := *c
		tc.Net = "tcp"
		r, _, err = tc.Exchange(m, server)
		if err != nil {
			return nil, fmt.Errorf("TCP retry after a truncated answer: %w", err)
		}
	}
	if err := checkQuestion(r, m); err != nil {
		return nil, err
	}
	return r, nil
}

// resolverQueryWithCD asks the configured recursive resolver and requires a
// NOERROR answer to the question asked. checkingDisabled is used only by the
// import advisory probe: that probe must still discover a zone whose current
// DNSSEC deployment is bogus, because repairing that deployment is its job.
func (v *Validator) resolverQueryWithCD(qname string, qtype uint16, checkingDisabled bool) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.RecursionDesired = true
	m.CheckingDisabled = checkingDisabled
	c := &dns.Client{Timeout: v.timeout}
	r, err := exchangeTC(c, m, v.resolverAddr())
	if err != nil {
		return nil, fmt.Errorf("%s %s lookup: %w", qname, dns.TypeToString[qtype], err)
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("%s %s lookup: %s", qname, dns.TypeToString[qtype], dns.RcodeToString[r.Rcode])
	}
	return r, nil
}

// resolverQuery performs ordinary validating recursive discovery.
func (v *Validator) resolverQuery(qname string, qtype uint16) (*dns.Msg, error) {
	return v.resolverQueryWithCD(qname, qtype, false)
}

// resolverQueryUnchecked requests data even when the recursive resolver finds
// the current DNSSEC chain bogus. The result is advisory, never a trust anchor.
func (v *Validator) resolverQueryUnchecked(qname string, qtype uint16) (*dns.Msg, error) {
	return v.resolverQueryWithCD(qname, qtype, true)
}

// nsNamesOf extracts the canonical NS names of zone from an NS answer: the
// Answer-section NS RRset owned by the zone, or — for a referral-shaped
// response — the Authority-section one.
func nsNamesOf(r *dns.Msg, zone string) []string {
	collect := func(rrs []dns.RR) []string {
		seen := map[string]bool{}
		var names []string
		for _, rr := range rrs {
			ns, ok := rr.(*dns.NS)
			if !ok || dns.CanonicalName(ns.Hdr.Name) != dns.CanonicalName(zone) {
				continue
			}
			name := dns.CanonicalName(ns.Ns)
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
		sort.Strings(names)
		return names
	}
	if names := collect(r.Answer); len(names) > 0 {
		return names
	}
	return collect(r.Ns)
}

// discoverNS returns every delegated nameserver of zone with every address
// it resolves to, IPv4 and IPv6. Glue from the Additional section is used
// only for an NS name inside the zone (in-bailiwick) and only for the
// address family it supplies; every other family, and every out-of-bailiwick
// name, is resolved through the recursive resolver. Policy: a lookup that
// fails (transport error, non-NOERROR rcode) fails discovery, a NOERROR
// answer with no address in that family simply contributes none, and a name
// left with no address at all fails discovery naming that nameserver. Only
// records owned by the queried name are accepted (an NS name must not be an
// alias, RFC 2181 §10.3).
func (v *Validator) discoverNS(zone string) ([]nsTarget, error) {
	return v.discoverNSWith(zone, v.resolverQuery)
}

// discoverNSUnchecked is the import-only discovery path for inspecting a
// deployment that may already be bogus. Its answers only drive advisory
// observations; parent-DS checks and rollover safety gates use discoverNS.
func (v *Validator) discoverNSUnchecked(zone string) ([]nsTarget, error) {
	return v.discoverNSWith(zone, v.resolverQueryUnchecked)
}

func (v *Validator) discoverNSWith(zone string, query func(string, uint16) (*dns.Msg, error)) ([]nsTarget, error) {
	zone = dns.Fqdn(zone)
	r, err := query(zone, dns.TypeNS)
	if err != nil {
		return nil, fmt.Errorf("NS lookup for %s: %w", zone, err)
	}
	names := nsNamesOf(r, zone)
	if len(names) == 0 {
		return nil, fmt.Errorf("no NS records found for %s", zone)
	}

	// In-bailiwick, owner-matched glue by name and family.
	glue := map[string]map[uint16][]string{}
	for _, rr := range r.Extra {
		var owner string
		var qtype uint16
		var ip string
		switch a := rr.(type) {
		case *dns.A:
			owner, qtype, ip = dns.CanonicalName(a.Hdr.Name), dns.TypeA, a.A.String()
		case *dns.AAAA:
			owner, qtype, ip = dns.CanonicalName(a.Hdr.Name), dns.TypeAAAA, a.AAAA.String()
		default:
			continue
		}
		if !dns.IsSubDomain(zone, owner) {
			continue
		}
		if glue[owner] == nil {
			glue[owner] = map[uint16][]string{}
		}
		glue[owner][qtype] = append(glue[owner][qtype], ip)
	}

	var targets []nsTarget
	for _, name := range names {
		seen := map[string]bool{}
		var addrs []string
		add := func(ip string) {
			a := net.JoinHostPort(ip, v.portOr())
			if !seen[a] {
				seen[a] = true
				addrs = append(addrs, a)
			}
		}
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			if ips := glue[name][qtype]; len(ips) > 0 {
				for _, ip := range ips {
					add(ip)
				}
				continue
			}
			ar, err := query(name, qtype)
			if err != nil {
				return nil, fmt.Errorf("nameserver %s of %s could not be resolved (delegation coverage incomplete): %w", name, zone, err)
			}
			for _, rr := range ar.Answer {
				switch a := rr.(type) {
				case *dns.A:
					if qtype == dns.TypeA && dns.CanonicalName(a.Hdr.Name) == name {
						add(a.A.String())
					}
				case *dns.AAAA:
					if qtype == dns.TypeAAAA && dns.CanonicalName(a.Hdr.Name) == name {
						add(a.AAAA.String())
					}
				}
			}
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("nameserver %s of %s resolved to no IPv4 or IPv6 address (delegation coverage incomplete)", name, zone)
		}
		sort.Strings(addrs)
		targets = append(targets, nsTarget{name: name, addrs: addrs})
	}
	return targets, nil
}

// flattenTargets returns the unique addresses of every target (sorted) and
// the nameserver names each address represents.
func flattenTargets(targets []nsTarget) (addrs []string, byName map[string][]string, namesOf map[string][]string) {
	byName = map[string][]string{}
	namesOf = map[string][]string{}
	seen := map[string]bool{}
	for _, t := range targets {
		byName[t.name] = append([]string(nil), t.addrs...)
		for _, a := range t.addrs {
			namesOf[a] = append(namesOf[a], t.name)
			if !seen[a] {
				seen[a] = true
				addrs = append(addrs, a)
			}
		}
	}
	sort.Strings(addrs)
	return addrs, byName, namesOf
}

// resolveAllNS returns the IP:port address of every nameserver of a zone,
// IPv4 and IPv6, deduplicated and sorted, or an error when the delegation
// cannot be covered completely.
func (v *Validator) resolveAllNS(zone string) ([]string, error) {
	targets, err := v.discoverNS(zone)
	if err != nil {
		return nil, err
	}
	addrs, _, _ := flattenTargets(targets)
	return addrs, nil
}

// ownerRecords returns the Answer-section records of type T owned by qname.
func ownerRecords[T dns.RR](msg *dns.Msg, qname string) []T {
	var out []T
	for _, rr := range msg.Answer {
		t, ok := rr.(T)
		if !ok {
			continue
		}
		if dns.CanonicalName(rr.Header().Name) != dns.CanonicalName(qname) {
			continue
		}
		out = append(out, t)
	}
	return out
}

// ProbeParentDS queries every authoritative server of the parent zone for the
// DS RRset of domain and reports, per KSK, whether its DS is present on all
// of them or absent from all of them, plus the largest DS TTL seen. A server
// that cannot be queried, or that does not answer authoritatively for
// exactly the question asked, makes the probe fail: a decision must not be
// taken on a partial view. Only DS records owned by the domain count.
//
// The two predicates are deliberately different (RDAYBLUEX-008):
//
//   - PresentOnAll (new-key presence, a rollover may proceed) requires an
//     EXACT supported digest (SHA-256 or SHA-384) derived from the DNSKEY on
//     every server.
//   - AbsentOnAll (old-key absence, a key may be retired) requires that NO DS
//     with the old key's key tag AND algorithm exists on any server,
//     irrespective of digest type or digest value: a SHA-1, unknown-digest,
//     malformed or wrong-digest DS with that tag/algorithm — and a colliding
//     tag/algorithm of some other key — still selects the old key at
//     resolvers, so waiting is safer than retiring it.
func (v *Validator) ProbeParentDS(domain string, ksks []*dns.DNSKEY) (signerpkg.ParentDSObservation, error) {
	obs := signerpkg.ParentDSObservation{PresentOnAll: map[uint16]bool{}, AbsentOnAll: map[uint16]bool{}}
	targets, err := v.discoverNS(findParentZone(domain))
	if err != nil {
		return obs, err
	}
	parents, byName, namesOf := flattenTargets(targets)
	obs.ByNameserver = byName
	expected := map[uint16][]*dns.DS{}
	algorithm := map[uint16]uint8{}
	for _, k := range ksks {
		if k == nil {
			continue
		}
		algorithm[k.KeyTag()] = k.Algorithm
		for _, dt := range []uint8{dns.SHA256, dns.SHA384} {
			if ds := k.ToDS(dt); ds != nil {
				expected[k.KeyTag()] = append(expected[k.KeyTag()], ds)
			}
		}
	}
	qname := dns.Fqdn(domain)
	exactCount := map[uint16]int{} // servers holding an exact supported digest for the key
	anyCount := map[uint16]int{}   // servers holding any DS with the key's tag and algorithm
	seenDS := map[string]bool{}    // DS records already listed in obs.DSRecords
	for _, server := range parents {
		msg, err := queryDirect(server, qname, dns.TypeDS, v.timeout)
		if err != nil {
			return obs, fmt.Errorf("DS query to parent server %s (%s) failed: %w", server, strings.Join(namesOf[server], ","), err)
		}
		obs.Servers = append(obs.Servers, server)
		dsRecords := ownerRecords[*dns.DS](msg, qname)
		for _, ds := range dsRecords {
			id := fmt.Sprintf("%d %d %d %s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToLower(ds.Digest))
			if !seenDS[id] {
				seenDS[id] = true
				obs.DSRecords = append(obs.DSRecords, ds)
			}
		}
		for _, ds := range dsRecords {
			if ds.Hdr.Ttl > obs.TTL {
				obs.TTL = ds.Hdr.Ttl
			}
		}
		for tag, alg := range algorithm {
			exact, any := false, false
			for _, ds := range dsRecords {
				if ds.KeyTag != tag || ds.Algorithm != alg {
					continue
				}
				any = true
				for _, exp := range expected[tag] {
					if ds.DigestType == exp.DigestType && strings.EqualFold(ds.Digest, exp.Digest) {
						exact = true
					}
				}
			}
			if exact {
				exactCount[tag]++
			}
			if any {
				anyCount[tag]++
			}
		}
	}
	for tag := range algorithm {
		obs.PresentOnAll[tag] = len(expected[tag]) > 0 && exactCount[tag] == len(parents)
		obs.AbsentOnAll[tag] = anyCount[tag] == 0
	}
	return obs, nil
}

// ProbePublishedSerial reports whether every authoritative server of the zone
// serves the SOA with the given serial (publication confirmation for
// dnssec.publication = "probe", RA6X-004). Any server that cannot be queried
// or serves another serial means "not yet"; a delegation that cannot be
// covered completely is an error. Only an authoritative SOA owned by the
// zone counts.
func (v *Validator) ProbePublishedSerial(domain string, serial uint32) (bool, string, error) {
	qname := dns.Fqdn(domain)
	servers, err := v.resolveAllNS(qname)
	if err != nil {
		return false, "", err
	}
	for _, server := range servers {
		msg, err := queryDirect(server, qname, dns.TypeSOA, v.timeout)
		if err != nil {
			return false, fmt.Sprintf("SOA query to %s failed: %v", server, err), nil
		}
		soas := ownerRecords[*dns.SOA](msg, qname)
		if len(soas) == 0 {
			return false, fmt.Sprintf("%s returned no SOA", server), nil
		}
		served := soas[len(soas)-1].Serial
		if served != serial {
			return false, fmt.Sprintf("%s serves serial %d, published %d", server, served, serial), nil
		}
	}
	return true, fmt.Sprintf("serial %d served by %d server(s)", serial, len(servers)), nil
}

// ProbeServedKeys asks every authoritative server of domain for its DNSKEY
// and SOA RRsets and reports what is published and which key tags sign them
// today. Discovery requests checking disabled so an already-bogus deployment
// can still be inspected; the result is advisory and cannot override the
// parent-trusted algorithm (signer.SelectImportKeys). Unlike the rollover
// probes it tolerates servers that do not answer — the result names them — but
// it fails when the delegation cannot be discovered or no server answers.
func (v *Validator) ProbeServedKeys(domain string) (signerpkg.ServedKeys, error) {
	var served signerpkg.ServedKeys
	qname := dns.Fqdn(domain)
	targets, err := v.discoverNSUnchecked(qname)
	if err != nil {
		return served, err
	}
	addrs, _, namesOf := flattenTargets(targets)
	now := time.Now()
	seen := map[string]bool{}
	sawSignature, sawValid := false, false
	note := func(sig *dns.RRSIG) {
		sawSignature = true
		if sig.ValidityPeriod(now) {
			sawValid = true
		}
	}
	for _, server := range addrs {
		dnskeyMsg, err := queryDirect(server, qname, dns.TypeDNSKEY, v.timeout)
		var soaMsg *dns.Msg
		if err == nil {
			soaMsg, err = queryDirect(server, qname, dns.TypeSOA, v.timeout)
		}
		if err != nil {
			served.Unreachable = append(served.Unreachable, fmt.Sprintf("%s (%s): %v", server, strings.Join(namesOf[server], ","), err))
			continue
		}
		served.Servers = append(served.Servers, server)
		for _, k := range ownerRecords[*dns.DNSKEY](dnskeyMsg, qname) {
			id := fmt.Sprintf("%d %d %d %s", k.Flags, k.Protocol, k.Algorithm, k.PublicKey)
			if !seen[id] {
				seen[id] = true
				served.DNSKEYs = append(served.DNSKEYs, k)
			}
			if k.Hdr.Ttl > served.DNSKEYTTL {
				served.DNSKEYTTL = k.Hdr.Ttl
			}
		}
		for _, sig := range ownerRecords[*dns.RRSIG](dnskeyMsg, qname) {
			if sig.TypeCovered == dns.TypeDNSKEY {
				served.DNSKEYSigners = appendTag(served.DNSKEYSigners, sig.KeyTag)
				note(sig)
			}
		}
		for _, sig := range ownerRecords[*dns.RRSIG](soaMsg, qname) {
			if sig.TypeCovered == dns.TypeSOA {
				served.SOASigners = appendTag(served.SOASigners, sig.KeyTag)
				note(sig)
			}
		}
		for _, soa := range ownerRecords[*dns.SOA](soaMsg, qname) {
			served.SOASerials = appendSerial(served.SOASerials, soa.Serial)
		}
	}
	if len(served.Servers) == 0 {
		return served, fmt.Errorf("no authoritative server of %s answered: %s", domain, strings.Join(served.Unreachable, "; "))
	}
	served.StaleSignatures = sawSignature && !sawValid
	return served, nil
}

// appendTag adds tag to tags unless it is already there.
func appendTag(tags []uint16, tag uint16) []uint16 {
	for _, t := range tags {
		if t == tag {
			return tags
		}
	}
	return append(tags, tag)
}

// appendSerial adds serial unless it is already present.
func appendSerial(serials []uint32, serial uint32) []uint32 {
	for _, s := range serials {
		if s == serial {
			return serials
		}
	}
	return append(serials, serial)
}
