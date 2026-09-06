package registrar

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"

	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
)

// ErrRegistrarDSEmpty is returned when a ReplaceDS sequence has already wiped
// the registrar's DS set (the DELETE succeeded) but could not restore the
// intended records afterward, so the parent is left holding zero DS — a silent
// DNSSEC outage (the zone downgrades to insecure delegation). Callers detect it
// with errors.Is and must escalate: log at Error with remediation and persist a
// zone warning so `status` stops reporting the zone healthy (R-004, R-032).
var ErrRegistrarDSEmpty = errors.New("registrar left zone with zero DS at parent (restore failed after clear)")

// Registrar is the minimal contract a registrar adapter must satisfy so the
// signer can manage DS records on its behalf.
type Registrar interface {
	Name() string
	GetDS(ctx context.Context, domain string) ([]*dns.DS, error)
	// AddDS publishes DS records alongside any existing ones. Used at KSK
	// rollover start so the old DS is never briefly absent.
	AddDS(ctx context.Context, domain string, ds []*dns.DS) error
	// ReplaceDS sets the registrar's DS record set for `domain` to exactly
	// the records provided. Implementations that lack atomic replace may
	// clear-then-set; callers accept that brief window.
	ReplaceDS(ctx context.Context, domain string, ds []*dns.DS) error
}

// RegistrarFor returns the registrar adapter configured for the given zone,
// or nil if the zone has no registrar field set or the named registrar is
// disabled/unconfigured. Errors indicate misconfiguration (name set but not
// resolvable); a nil registrar with nil error means "not opted in".
func RegistrarFor(cfg *config.Config, domain string) (Registrar, error) {
	zc, ok := cfg.Zones[domain]
	if !ok || zc.Registrar == "" {
		return nil, nil
	}
	switch strings.ToLower(zc.Registrar) {
	case "dynadot":
		if !cfg.Registrar.Dynadot.Enabled {
			return nil, fmt.Errorf("zone %q has registrar=\"dynadot\" but [registrar.dynadot] is not enabled", domain)
		}
		return NewDynadotClient(&cfg.Registrar.Dynadot)
	default:
		return nil, fmt.Errorf("zone %q references unknown registrar %q", domain, zc.Registrar)
	}
}

// BuildDSSet computes the DS record set the registrar should hold for a zone,
// given the KSK(s) currently in use. During a KSK or algorithm rollover, both
// old and new KSK belong in the set; otherwise just the active KSK.
func BuildDSSet(cfg *config.Config, state *statepkg.State, domain string) ([]*dns.DS, error) {
	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return nil, fmt.Errorf("zone %s not managed", domain)
	}
	if zoneState.KSK == nil {
		return nil, fmt.Errorf("zone %s has no KSK", domain)
	}

	digestType := cfg.Registrar.DigestType()
	keyGen := signerpkg.NewKeyGenerator(cfg)

	var out []*dns.DS
	// Active KSK (always present). Key filenames use the primary "ksk" slot.
	// Only the public halves are needed to compute DS records.
	ksk, err := keyGen.LoadPublicKey(domain, "ksk")
	if err != nil {
		return nil, fmt.Errorf("loading active KSK: %w", err)
	}
	out = append(out, ksk.ToDS(digestType))

	// During KSK or algorithm rollover, include the old KSK's DS as well —
	// until `rollover complete` is run, both DS records must be present at
	// the parent so resolvers mid-transition can validate either chain.
	if zoneState.Rollover != nil && (zoneState.Rollover.Type == "ksk" || zoneState.Rollover.Type == "algorithm") {
		oldKSK, err := keyGen.LoadPublicKeyByID(domain, "ksk", zoneState.Rollover.OldKeyID)
		if err != nil {
			// The old KSK's DS MUST stay at the parent until `rollover complete`.
			// If the backed-up old key can't be loaded we cannot compute its DS,
			// and handing a new-KSK-only set to ReplaceDS would DELETE the old DS
			// mid-rollover — every resolver still validating via the old chain
			// goes bogus. Refuse rather than silently shrink the set to new-only
			// (R-031; the missing-backup root cause is R-027).
			return nil, fmt.Errorf("zone %s: cannot load backed-up old KSK (id %d) during %s rollover; refusing to build a DS set that would drop the old DS at the parent: %w",
				domain, zoneState.Rollover.OldKeyID, zoneState.Rollover.Type, err)
		}
		out = append(out, oldKSK.ToDS(digestType))
	}

	return out, nil
}

// dsKey returns a comparable key for a DS record (independent of field order
// or case in the digest).
func dsKey(ds *dns.DS) string {
	return fmt.Sprintf("%d/%d/%d/%s", ds.KeyTag, ds.Algorithm, ds.DigestType, strings.ToLower(ds.Digest))
}

// CompareDSSets returns (missing, extra) — DS records that are in `want` but
// not `have`, and DS records in `have` but not `want`, respectively. Useful
// for drift detection in `registrar verify`.
func CompareDSSets(want, have []*dns.DS) (missing, extra []*dns.DS) {
	wantMap := make(map[string]*dns.DS, len(want))
	for _, d := range want {
		wantMap[dsKey(d)] = d
	}
	haveMap := make(map[string]*dns.DS, len(have))
	for _, d := range have {
		haveMap[dsKey(d)] = d
	}
	for k, d := range wantMap {
		if _, ok := haveMap[k]; !ok {
			missing = append(missing, d)
		}
	}
	for k, d := range haveMap {
		if _, ok := wantMap[k]; !ok {
			extra = append(extra, d)
		}
	}
	sort.Slice(missing, func(i, j int) bool { return dsKey(missing[i]) < dsKey(missing[j]) })
	sort.Slice(extra, func(i, j int) bool { return dsKey(extra[i]) < dsKey(extra[j]) })
	return
}

// Version is the build identifier used in the default Dynadot User-Agent. The
// root package sets it from its ldflags-injected main.Version at startup; it
// defaults to "dev" for tests and un-stamped builds.
var Version = "dev"
