package signer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// Canonical owner identity and the per-snapshot zone model (RA6X-028,
// RA6X-053).
//
// DNS owner names are compared by their wire-format labels, not by their
// presentation spelling: `www`, `WWW` and `\119ww` are the same label, while
// `a\.b` (one label containing a dot) and `a.b` (two labels) are different
// names. canonicalName maps every spelling of a wire name to one canonical
// presentation string, and every place that groups or compares owners — RRset
// formation, delegation and occlusion checks, empty non-terminals, denial-chain
// owners and ordering — keys on it. Records keep their original spelling in
// the output; signing operates on the complete semantic RRset.
//
// zoneModel indexes one immutable input snapshot once and is shared by chain
// generation, signing and self-verification. Occlusion is answered by walking
// a name's bounded ancestor list against the delegation/DNAME index, so the
// work is proportional to label depth rather than to names × cuts.

// canonicalName returns the canonical presentation of a domain name: every
// label decoded to its wire octets (decimal and single-character escapes
// resolved), ASCII letters lowercased, and re-encoded so that only dots,
// backslashes and non-printable octets are escaped. Equal wire names map to
// equal strings; distinct wire names never collide.
func canonicalName(name string) string {
	name = dns.Fqdn(name)
	if name == "." {
		return "."
	}
	var b strings.Builder
	for _, label := range dns.SplitDomainName(name) {
		b.WriteString(canonicalLabel(label))
		b.WriteByte('.')
	}
	return b.String()
}

// canonicalLabel canonicalizes one presentation-format label.
func canonicalLabel(label string) string {
	var b strings.Builder
	for _, c := range canonicalLabelBytes(label) {
		switch {
		case c == '.':
			b.WriteString(`\.`)
		case c == '\\':
			b.WriteString(`\\`)
		case c < '!' || c > '~':
			fmt.Fprintf(&b, `\%03d`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// canonicalLabels returns the canonical labels of a name, most specific first.
func canonicalLabels(name string) []string {
	canon := canonicalName(name)
	if canon == "." {
		return nil
	}
	return dns.SplitDomainName(canon)
}

// joinLabels renders canonical labels as a canonical name.
func joinLabels(labels []string) string {
	if len(labels) == 0 {
		return "."
	}
	return strings.Join(labels, ".") + "."
}

// labelsWithin reports whether name (as canonical labels) is at or below
// apex (as canonical labels).
func labelsWithin(name, apex []string) bool {
	if len(name) < len(apex) {
		return false
	}
	off := len(name) - len(apex)
	for i := range apex {
		if name[off+i] != apex[i] {
			return false
		}
	}
	return true
}

// ownerInfo is what one canonical owner holds in the input snapshot.
type ownerInfo struct {
	name   string         // canonical name
	labels []string       // canonical labels, most specific first
	types  map[uint16]int // record count per type
}

// zoneModel is the canonical index of one input snapshot.
type zoneModel struct {
	apex        string
	apexLabels  []string
	owners      map[string]*ownerInfo // every owner, occluded or not
	delegations map[string]bool       // NS owners below the apex
	dnames      map[string]bool       // DNAME owners
	occluded    map[string]bool       // memoized occlusion answers
}

// newZoneModel indexes records by canonical owner.
func newZoneModel(domain string, records []dns.RR) *zoneModel {
	apex := canonicalName(domain)
	m := &zoneModel{
		apex:        apex,
		apexLabels:  dns.SplitDomainName(apex),
		owners:      make(map[string]*ownerInfo),
		delegations: make(map[string]bool),
		dnames:      make(map[string]bool),
		occluded:    make(map[string]bool),
	}
	for _, rr := range records {
		m.add(rr)
	}
	return m
}

// add indexes one record.
func (m *zoneModel) add(rr dns.RR) *ownerInfo {
	h := rr.Header()
	name := canonicalName(h.Name)
	oi := m.owners[name]
	if oi == nil {
		oi = &ownerInfo{name: name, labels: dns.SplitDomainName(name), types: make(map[uint16]int)}
		m.owners[name] = oi
	}
	oi.types[h.Rrtype]++
	switch h.Rrtype {
	case dns.TypeNS:
		if name != m.apex {
			m.delegations[name] = true
		}
	case dns.TypeDNAME:
		m.dnames[name] = true
	}
	return oi
}

// canon returns the canonical owner of a record.
func (m *zoneModel) canon(rr dns.RR) string {
	return canonicalName(rr.Header().Name)
}

// within reports whether a canonical owner lies at or below the apex.
func (m *zoneModel) within(name string) bool {
	return labelsWithin(dns.SplitDomainName(name), m.apexLabels)
}

// isDelegation reports whether a canonical owner is a delegation point.
func (m *zoneModel) isDelegation(name string) bool {
	return m.delegations[name]
}

// isOccluded reports whether a canonical owner sits strictly below a
// delegation point or a DNAME owner, i.e. is not authoritative in this zone
// (RFC 4035 §2.2, RFC 6672 §2.4). Each proper ancestor is looked up once, so
// the cost is bounded by the name's depth.
func (m *zoneModel) isOccluded(name string) bool {
	if len(m.delegations) == 0 && len(m.dnames) == 0 {
		return false
	}
	if v, ok := m.occluded[name]; ok {
		return v
	}
	labels := dns.SplitDomainName(name)
	result := false
	for i := 1; i < len(labels)-len(m.apexLabels); i++ {
		anc := joinLabels(labels[i:])
		if m.delegations[anc] || m.dnames[anc] {
			result = true
			break
		}
	}
	m.occluded[name] = result
	return result
}

// occludingDNAME returns the DNAME owner above a canonical name, if any.
func (m *zoneModel) occludingDNAME(name string) (string, bool) {
	if len(m.dnames) == 0 {
		return "", false
	}
	labels := dns.SplitDomainName(name)
	for i := 1; i < len(labels)-len(m.apexLabels); i++ {
		anc := joinLabels(labels[i:])
		if m.dnames[anc] {
			return anc, true
		}
	}
	return "", false
}

// signable reports whether an RRset at a canonical owner is signed by this
// zone: not occluded, and at a delegation point only DS and NSEC (RFC 4035
// §2.2).
func (m *zoneModel) signable(name string, rrtype uint16) bool {
	if m.isOccluded(name) {
		return false
	}
	if m.isDelegation(name) && rrtype != dns.TypeDS && rrtype != dns.TypeNSEC {
		return false
	}
	return true
}

// authoritativeOwners returns every non-occluded owner in canonical order.
func (m *zoneModel) authoritativeOwners() []string {
	var names []string
	for name := range m.owners {
		if !m.isOccluded(name) {
			names = append(names, name)
		}
	}
	sort.Slice(names, func(i, j int) bool { return canonicalLess(names[i], names[j]) })
	return names
}

// emptyNonTerminals returns the names strictly between the authoritative
// owners and the apex that hold no records themselves (RFC 5155 §7.1), in
// canonical order.
func (m *zoneModel) emptyNonTerminals() []string {
	ents := make(map[string]bool)
	for _, name := range m.authoritativeOwners() {
		labels := dns.SplitDomainName(name)
		for i := 1; i < len(labels)-len(m.apexLabels); i++ {
			anc := joinLabels(labels[i:])
			if m.owners[anc] == nil {
				ents[anc] = true
			}
		}
	}
	var names []string
	for name := range ents {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return canonicalLess(names[i], names[j]) })
	return names
}

// denialTypes returns the type bitmap the denial record for a canonical owner
// must carry: at a delegation point NS and DS (if present); elsewhere every
// data type present. nsec3 selects RFC 5155 §7.1 rules (RRSIG only where the
// zone signs something at the name, NSEC3PARAM at the apex, no self-type)
// versus RFC 4035 §2.3 rules (NSEC and RRSIG always present).
func (m *zoneModel) denialTypes(name string, nsec3 bool) []uint16 {
	oi := m.owners[name]
	set := make(map[uint16]bool)
	if oi != nil {
		if m.isDelegation(name) {
			set[dns.TypeNS] = true
			if oi.types[dns.TypeDS] > 0 {
				set[dns.TypeDS] = true
				if nsec3 {
					set[dns.TypeRRSIG] = true
				}
			}
		} else {
			for t := range oi.types {
				set[t] = true
			}
			if nsec3 {
				set[dns.TypeRRSIG] = true
			}
		}
	}
	if nsec3 {
		if name == m.apex && oi != nil {
			set[dns.TypeNSEC3PARAM] = true
		}
	} else {
		set[dns.TypeNSEC] = true
		set[dns.TypeRRSIG] = true
	}
	types := make([]uint16, 0, len(set))
	for t := range set {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	return types
}

// rrsetKey identifies an RRset by canonical owner and type.
type rrsetKey struct {
	name   string
	rrtype uint16
}

// groupRRsets groups records into semantic RRsets by canonical owner and type,
// preserving each record's original presentation. RRSIGs are returned
// separately.
func groupRRsets(records []dns.RR) (map[rrsetKey][]dns.RR, []*dns.RRSIG) {
	rrsets := make(map[rrsetKey][]dns.RR)
	var rrsigs []*dns.RRSIG
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, sig)
			continue
		}
		k := rrsetKey{canonicalName(rr.Header().Name), rr.Header().Rrtype}
		rrsets[k] = append(rrsets[k], rr)
	}
	return rrsets, rrsigs
}

// canonicalRRset returns copies of an RRset with every owner rewritten to the
// canonical spelling, which is what the wire-format signature covers (RFC 4034
// §6.2). The records that will be written are never mutated.
func canonicalRRset(rrset []dns.RR) []dns.RR {
	out := make([]dns.RR, len(rrset))
	for i, rr := range rrset {
		cp := dns.Copy(rr)
		cp.Header().Name = canonicalName(cp.Header().Name)
		out[i] = cp
	}
	return out
}
