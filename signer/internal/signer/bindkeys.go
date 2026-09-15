package signer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Taking over a zone that another tool signed (dnssec-keygen/dnssec-signzone,
// ldns-keygen/ldns-signzone, ...) is anchored at the parent: the KSK whose DS
// the parent holds determines the algorithm. A usable ZSK of that algorithm
// completes the chain; the one signing the served zone is preferred only when
// it is compatible, because the served deployment may be what import needs to
// repair. `import --keys-dir` points at the other tool's key directory;
// ScanBindKeys describes every pair found there and SelectImportKeys chooses
// the pair — or says exactly why none works. Everything here is pure except
// the file reads.

// bindKeyFile matches BIND/ldns key file names: K<owner>.+<alg>+<tag>.<ext>.
var bindKeyFile = regexp.MustCompile(`^K(.+)\.\+(\d{3})\+(\d{5})\.(key|private)$`)

// bindCreatedLayout is the timestamp layout of the Created field in BIND key
// files (and in this signer's own).
const bindCreatedLayout = "20060102150405"

// ImportCandidate is one key pair found for a zone: what it is, where it is
// and, when it cannot be imported, why.
type ImportCandidate struct {
	Base      string // path of the pair without the .key/.private extension
	Tag       uint16
	Algorithm uint8
	Flags     uint16
	Role      string    // "ksk" (flags 257), "zsk" (256) or "" for anything else
	Bits      int       // RSA modulus size; 0 for other algorithms
	Created   time.Time // the private file's Created field, else the .key mtime; zero if unknown
	DNSKEY    *dns.DNSKEY
	Private   []byte // in-memory private key; nil unless the pair is usable
	Problem   string // why the pair cannot be imported; empty when it can
}

// Usable reports whether the pair passed every import check.
func (c *ImportCandidate) Usable() bool { return c.Problem == "" }

// Name is the short operator-facing identity of the candidate.
func (c *ImportCandidate) Name() string {
	if c.DNSKEY == nil {
		return filepath.Base(c.Base)
	}
	return fmt.Sprintf("%d (%s)", c.Tag, AlgorithmName(c.Algorithm))
}

// DescribeCandidate loads, classifies and validates the pair at base for
// domain. A pair that cannot be used is still described, with Problem set,
// so the operator sees every key that was found.
func DescribeCandidate(domain, base string) *ImportCandidate {
	c := &ImportCandidate{Base: base}
	if m := bindKeyFile.FindStringSubmatch(filepath.Base(base) + ".key"); m != nil {
		// Identity from the file name, so an unparseable pair is still listed
		// as the key its name claims it to be.
		fmt.Sscanf(m[2], "%d", &c.Algorithm)
		fmt.Sscanf(m[3], "%d", &c.Tag)
	}

	keyData, keyErr := os.ReadFile(base + ".key")
	if keyErr == nil {
		dnskey, err := ParseDNSKEYFromFile(string(keyData))
		if err != nil {
			keyErr = fmt.Errorf("parsing %s.key: %w", base, err)
		} else {
			c.DNSKEY = dnskey
			c.Tag, c.Algorithm, c.Flags = dnskey.KeyTag(), dnskey.Algorithm, dnskey.Flags
			c.Bits = RSAKeyBits(dnskey)
			switch dnskey.Flags {
			case 257:
				c.Role = "ksk"
			case 256:
				c.Role = "zsk"
			}
		}
	}
	c.Created = candidateCreated(base)
	if keyErr != nil {
		c.Problem = keyErr.Error()
		return c
	}
	if c.Role == "" {
		revoked := ""
		if c.Flags&0x80 != 0 {
			revoked = " (the REVOKE bit is set)"
		}
		c.Problem = fmt.Sprintf("DNSKEY flags %d are neither KSK (257) nor ZSK (256)%s", c.Flags, revoked)
		return c
	}

	privData, err := os.ReadFile(base + ".private")
	if err != nil {
		c.Problem = fmt.Sprintf("reading %s.private: %v", base, err)
		return c
	}
	privateKey, err := ParsePrivateKeyFromFile(string(privData))
	if err != nil {
		c.Problem = fmt.Sprintf("parsing %s.private: %v", base, err)
		return c
	}
	if err := ValidateKeyForImport(domain, c.Role, c.DNSKEY, privateKey); err != nil {
		c.Problem = err.Error()
		return c
	}
	c.Private = privateKey
	return c
}

// candidateCreated reads the Created field of the private half, falling back
// to the public half's modification time.
func candidateCreated(base string) time.Time {
	if data, err := os.ReadFile(base + ".private"); err == nil {
		if v, ok := parsePrivateKeyFields(string(data))["created"]; ok {
			stamp, _, _ := strings.Cut(v, " ")
			if t, err := time.Parse(bindCreatedLayout, stamp); err == nil {
				return t.UTC()
			}
		}
	}
	if info, err := os.Stat(base + ".key"); err == nil {
		return info.ModTime().UTC()
	}
	return time.Time{}
}

// ScanBindKeys describes every BIND-style key pair for domain in dir. Files
// named for another owner are ignored; everything else is listed, usable or
// not. A .key without its .private (or the reverse) is listed with the
// problem. The result is ordered newest first, then by key tag.
func ScanBindKeys(dir, domain string) ([]*ImportCandidate, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading key directory %s: %w", dir, err)
	}
	want := dns.CanonicalName(domain)
	bases := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := bindKeyFile.FindStringSubmatch(e.Name())
		if m == nil || dns.CanonicalName(m[1]) != want {
			continue
		}
		bases[filepath.Join(dir, strings.TrimSuffix(e.Name(), "."+m[4]))] = true
	}
	cands := make([]*ImportCandidate, 0, len(bases))
	for base := range bases {
		cands = append(cands, DescribeCandidate(domain, base))
	}
	sortCandidates(cands)
	return cands, nil
}

// sortCandidates orders newest first, then by key tag, for stable output.
func sortCandidates(cands []*ImportCandidate) {
	sort.SliceStable(cands, func(i, j int) bool {
		if !cands[i].Created.Equal(cands[j].Created) {
			return cands[i].Created.After(cands[j].Created)
		}
		return cands[i].Tag < cands[j].Tag
	})
}

// ServedKeys is what the zone's own authoritative servers publish right now.
type ServedKeys struct {
	Servers     []string // servers that answered
	Unreachable []string // servers that did not, with the reason
	// DNSKEYs is the union of the DNSKEY RRsets served; DNSKEYTTL the largest
	// TTL seen on them.
	DNSKEYs   []*dns.DNSKEY
	DNSKEYTTL uint32
	// SOASigners and DNSKEYSigners are the key tags of the RRSIGs served over
	// the SOA and the DNSKEY RRset, whatever their validity.
	SOASigners    []uint16
	DNSKEYSigners []uint16
	// SOASerials is the union of apex serials returned by the authoritative
	// servers. Import uses it to avoid publishing a serial they will not take.
	SOASerials []uint32
	// StaleSignatures is set when signatures are served but every one of them
	// is outside its validity window: the zone is already failing validation.
	StaleSignatures bool
}

// Published reports whether a key with exactly this material is served.
func (s ServedKeys) Published(k *dns.DNSKEY) bool {
	for _, served := range s.DNSKEYs {
		if samePublicKey(served, k) {
			return true
		}
	}
	return false
}

// ImportObservation is what the network says about the zone as served today.
// Zero-valued fields mean "not observed".
type ImportObservation struct {
	// ParentProbed is set when every parent server answered the DS query;
	// ParentDS is then the union of DS records they hold for the zone, and
	// DSPresentOnAll / DSAbsentOnAll are per KSK key tag as ProbeParentDS
	// reports them.
	ParentProbed   bool
	ParentDS       []*dns.DS
	DSPresentOnAll map[uint16]bool
	DSAbsentOnAll  map[uint16]bool
	// ServedProbed is set when at least one authoritative server of the zone
	// answered; ServedError says why none did.
	ServedProbed bool
	ServedError  string
	Served       ServedKeys
}

// TagChoice is an operator's explicit choice of a key by tag.
type TagChoice struct {
	Set bool
	Tag uint16
}

// ImportSelection is the pair to import and the reasoning the operator sees.
type ImportSelection struct {
	KSK, ZSK             *ImportCandidate
	KSKReason, ZSKReason string
	// Warnings are conditions to read before proceeding; none of them stops
	// the import by itself.
	Warnings []string
	// DSMissing is set when the parent holds DS records and none of them is
	// the chosen KSK's on any parent server: serving this zone would make it
	// bogus. The caller decides whether an explicit override allows it.
	DSMissing bool
}

// SelectImportKeys chooses the KSK and ZSK to import from cands. An explicit
// choice is honoured after the same checks; otherwise the KSK is the usable
// one whose DS every parent server holds. That parent-trusted KSK fixes the
// algorithm; among usable ZSKs of that algorithm, the one signing the served
// zone is preferred, then one published there, then the newest. Thus an
// incompatible served deployment never displaces the recoverable chain.
// Without a parent observation the choice must be unambiguous or explicit.
// The error names what stands in the way.
func SelectImportKeys(cands []*ImportCandidate, obs ImportObservation, ksk, zsk TagChoice) (*ImportSelection, error) {
	sel := &ImportSelection{}
	var err error
	if sel.KSK, sel.KSKReason, err = chooseKSK(cands, obs, ksk); err != nil {
		return nil, err
	}
	if sel.ZSK, sel.ZSKReason, err = chooseZSK(cands, obs, zsk, sel.KSK); err != nil {
		return nil, err
	}
	sel.Warnings, sel.DSMissing = importWarnings(sel, obs)
	return sel, nil
}

func chooseKSK(cands []*ImportCandidate, obs ImportObservation, choice TagChoice) (*ImportCandidate, string, error) {
	if choice.Set {
		c, err := pickByTag(cands, choice.Tag, "ksk")
		if err != nil {
			return nil, "", err
		}
		return c, "chosen with --ksk", nil
	}
	usable := usableOfRole(cands, "ksk")
	if len(usable) == 0 {
		return nil, "", fmt.Errorf("no usable KSK among the keys found%s", problemSummary(cands, "ksk"))
	}
	if !obs.ParentProbed {
		if len(usable) == 1 {
			return usable[0], "the only usable KSK found (the parent's DS was not checked)", nil
		}
		return nil, "", fmt.Errorf("%d usable KSKs found (%s) and the parent's DS was not checked; choose one with --ksk <tag>", len(usable), tagList(usable))
	}
	if len(obs.ParentDS) == 0 {
		ranked := rankCandidates(usable, obs.Served.DNSKEYSigners)
		return ranked[0], "the parent holds no DS for the zone, so any KSK serves; newest usable one (publish its DS to enable validation)", nil
	}
	var matching []*ImportCandidate
	for _, c := range usable {
		if obs.DSPresentOnAll[c.Tag] {
			matching = append(matching, c)
		}
	}
	if len(matching) == 0 {
		return nil, "", fmt.Errorf("none of the usable KSKs (%s) has its DS at every parent server; the parent holds %s%s", tagList(usable), DescribeDS(obs.ParentDS), dsNamingUnusable(cands, obs.ParentDS))
	}
	ranked := rankCandidates(matching, obs.Served.DNSKEYSigners)
	reason := "its DS is at every parent server"
	switch {
	case len(matching) == 1:
	case containsTag(obs.Served.DNSKEYSigners, ranked[0].Tag):
		reason += " and it signs the served DNSKEY RRset (also eligible: " + tagList(matching[1:]) + ")"
	default:
		reason += "; newest of the eligible " + tagList(matching)
	}
	return ranked[0], reason, nil
}

func chooseZSK(cands []*ImportCandidate, obs ImportObservation, choice TagChoice, ksk *ImportCandidate) (*ImportCandidate, string, error) {
	if choice.Set {
		c, err := pickByTag(cands, choice.Tag, "zsk")
		if err != nil {
			return nil, "", err
		}
		if c.Algorithm != ksk.Algorithm {
			return nil, "", fmt.Errorf("ZSK %d uses %s but KSK %d uses %s: a zone's KSK and ZSK must share an algorithm (RFC 6840 §5.11); a genuine algorithm change goes through `rollover algorithm` after the import",
				c.Tag, AlgorithmName(c.Algorithm), ksk.Tag, AlgorithmName(ksk.Algorithm))
		}
		return c, "chosen with --zsk", nil
	}
	var usable []*ImportCandidate
	for _, c := range usableOfRole(cands, "zsk") {
		if c.Algorithm == ksk.Algorithm {
			usable = append(usable, c)
		}
	}
	if len(usable) == 0 {
		return nil, "", fmt.Errorf("no usable ZSK with the KSK's algorithm %s among the keys found%s", AlgorithmName(ksk.Algorithm), problemSummary(cands, "zsk"))
	}
	ranked := rankZSK(usable, obs)
	c := ranked[0]
	var reason string
	switch {
	case obs.ServedProbed && containsTag(obs.Served.SOASigners, c.Tag):
		reason = "it signs the served zone"
	case obs.ServedProbed && obs.Served.Published(c.DNSKEY):
		reason = "it is in the served DNSKEY RRset (no served signature by it was seen)"
	case len(usable) == 1:
		reason = "the only usable ZSK with the KSK's algorithm"
	default:
		reason = "newest usable ZSK with the KSK's algorithm (also eligible: " + tagList(ranked[1:]) + ")"
	}
	if !obs.ServedProbed {
		reason += " (the served zone was not checked)"
	}
	return c, reason, nil
}

// importWarnings lists what the operator should know about the selection
// against what is served today, and whether the parent's DS contradicts it.
func importWarnings(sel *ImportSelection, obs ImportObservation) (warnings []string, dsMissing bool) {
	if obs.ParentProbed {
		switch {
		case len(obs.ParentDS) == 0:
			warnings = append(warnings, fmt.Sprintf("the parent holds no DS for the zone: the delegation stays insecure until you publish the DS of KSK %d", sel.KSK.Tag))
		case obs.DSPresentOnAll[sel.KSK.Tag]:
		case obs.DSAbsentOnAll[sel.KSK.Tag]:
			dsMissing = true
			warnings = append(warnings, fmt.Sprintf("the parent holds %s, none of which is the DS of KSK %d: resolvers will treat the zone as bogus once this signed zone is served, until the parent's DS is changed", DescribeDS(obs.ParentDS), sel.KSK.Tag))
		default:
			warnings = append(warnings, fmt.Sprintf("the DS of KSK %d is on some parent servers but not all (still propagating?); resolvers reaching the others cannot validate the zone yet", sel.KSK.Tag))
		}
	} else {
		warnings = append(warnings, "the parent's DS records were not checked: make sure the parent holds the DS shown below before this signed zone is served")
	}
	if !obs.ServedProbed {
		if obs.ServedError != "" {
			warnings = append(warnings, "the zone's authoritative servers could not be consulted ("+obs.ServedError+"); the choice of ZSK is not verified against what resolvers may have cached")
		}
		return warnings, dsMissing
	}
	s := obs.Served
	if len(s.Unreachable) > 0 {
		warnings = append(warnings, "some authoritative servers did not answer: "+strings.Join(s.Unreachable, "; "))
	}
	switch {
	case len(s.DNSKEYs) == 0:
		warnings = append(warnings, "no DNSKEY RRset is served today: the zone is currently unsigned at its authoritative servers")
	case obs.ParentProbed && obs.DSPresentOnAll[sel.KSK.Tag] && !s.Published(sel.KSK.DNSKEY):
		warnings = append(warnings, fmt.Sprintf("the served DNSKEY RRset does not contain KSK %d trusted by the parent DS, so that deployment cannot satisfy the chain; this import installs that KSK with compatible ZSK %d", sel.KSK.Tag, sel.ZSK.Tag))
	case s.StaleSignatures:
		warnings = append(warnings, "every signature served today has expired (or is not yet valid): the zone is already failing validation, so there are no cached signatures to preserve")
	default:
		if !s.Published(sel.ZSK.DNSKEY) {
			warnings = append(warnings, fmt.Sprintf("ZSK %d is not in the DNSKEY RRset served today (TTL %ds): resolvers holding that RRset cannot validate the new signatures until it expires", sel.ZSK.Tag, s.DNSKEYTTL))
		}
		if len(s.SOASigners) > 0 && !containsTag(s.SOASigners, sel.ZSK.Tag) {
			warnings = append(warnings, fmt.Sprintf("the served zone is signed by ZSK %s, which this import does not publish: resolvers holding those signatures cannot validate them once the served DNSKEY RRset expires from their cache", tagsString(s.SOASigners)))
		}
	}
	return warnings, dsMissing
}

// pickByTag finds the candidate with tag in the requested role and confirms it
// is usable.
func pickByTag(cands []*ImportCandidate, tag uint16, role string) (*ImportCandidate, error) {
	var found *ImportCandidate
	for _, c := range cands {
		if c.Tag != tag {
			continue
		}
		if c.Role == role {
			found = c
			break
		}
		if found == nil {
			found = c
		}
	}
	switch {
	case found == nil:
		return nil, fmt.Errorf("no key with tag %d was found", tag)
	case found.Role != role:
		what := "neither a KSK nor a ZSK"
		if found.Role != "" {
			what = "a " + strings.ToUpper(found.Role)
		}
		return nil, fmt.Errorf("key %d is %s, not a %s", tag, what, strings.ToUpper(role))
	case !found.Usable():
		return nil, fmt.Errorf("key %d cannot be imported: %s", tag, found.Problem)
	}
	return found, nil
}

func usableOfRole(cands []*ImportCandidate, role string) []*ImportCandidate {
	var out []*ImportCandidate
	for _, c := range cands {
		if c.Role == role && c.Usable() {
			out = append(out, c)
		}
	}
	return out
}

// rankCandidates orders cands so that keys whose tag is in prefer come first,
// then newest, then lowest tag. It never returns an empty slice for a
// non-empty input.
func rankCandidates(cands []*ImportCandidate, prefer []uint16) []*ImportCandidate {
	ranked := append([]*ImportCandidate(nil), cands...)
	sortCandidates(ranked)
	sort.SliceStable(ranked, func(i, j int) bool {
		return containsTag(prefer, ranked[i].Tag) && !containsTag(prefer, ranked[j].Tag)
	})
	return ranked
}

// rankZSK prefers the ZSK signing the served zone, then one that is
// published, then the newest.
func rankZSK(cands []*ImportCandidate, obs ImportObservation) []*ImportCandidate {
	ranked := append([]*ImportCandidate(nil), cands...)
	sortCandidates(ranked)
	if !obs.ServedProbed {
		return ranked
	}
	score := func(c *ImportCandidate) int {
		switch {
		case containsTag(obs.Served.SOASigners, c.Tag):
			return 2
		case obs.Served.Published(c.DNSKEY):
			return 1
		}
		return 0
	}
	sort.SliceStable(ranked, func(i, j int) bool { return score(ranked[i]) > score(ranked[j]) })
	return ranked
}

// problemSummary lists why each candidate of a role is unusable, for an error
// that would otherwise just say "none".
func problemSummary(cands []*ImportCandidate, role string) string {
	var parts []string
	for _, c := range cands {
		if c.Role == role || (c.Role == "" && c.DNSKEY == nil) {
			if !c.Usable() {
				parts = append(parts, fmt.Sprintf("%s: %s", c.Name(), c.Problem))
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// dsNamingUnusable explains a parent DS that names a key which was found but
// cannot be imported — typically a SHA-1 key — since that is the one fact the
// operator needs in order to fix the situation.
func dsNamingUnusable(cands []*ImportCandidate, parentDS []*dns.DS) string {
	var parts []string
	for _, ds := range parentDS {
		for _, c := range cands {
			if c.Tag == ds.KeyTag && c.Algorithm == ds.Algorithm && !c.Usable() {
				parts = append(parts, fmt.Sprintf("the DS for key %d names a key that was found but cannot be imported: %s", c.Tag, c.Problem))
				break
			}
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "; " + strings.Join(parts, "; ")
}

// DescribeDS renders DS records as "tag/algorithm/digest" triples.
func DescribeDS(ds []*dns.DS) string {
	if len(ds) == 0 {
		return "no DS records"
	}
	parts := make([]string, 0, len(ds))
	for _, d := range ds {
		digest := dns.HashToString[d.DigestType]
		if digest == "" {
			digest = fmt.Sprintf("digest type %d", d.DigestType)
		}
		parts = append(parts, fmt.Sprintf("%d/%s/%s", d.KeyTag, AlgorithmName(d.Algorithm), digest))
	}
	return "DS " + strings.Join(parts, ", ")
}

func containsTag(tags []uint16, tag uint16) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func tagList(cands []*ImportCandidate) string {
	parts := make([]string, 0, len(cands))
	for _, c := range cands {
		parts = append(parts, fmt.Sprint(c.Tag))
	}
	return strings.Join(parts, ", ")
}

func tagsString(tags []uint16) string {
	parts := make([]string, 0, len(tags))
	for _, t := range tags {
		parts = append(parts, fmt.Sprint(t))
	}
	return strings.Join(parts, ", ")
}
