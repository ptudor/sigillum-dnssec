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

// IncludesOldDS reports whether a rollover phase still requires the OLD KSK's
// DS at the parent (RDAYBLUEX-007). The desired set is phase-aware:
//
//	KSK rollover:        ds_add_wait → old + new;
//	                     ds_propagation_wait, retiring → new only (the new DS
//	                     was observed at every parent server; the workflow
//	                     authorizes old-DS removal from here and a later
//	                     `registrar push` must never resurrect the old DS)
//	Algorithm rollover:  algo_ds_add_wait, algo_ds_propagation_wait → old + new
//	                     (RFC 6781 §4.1.4: both DS through the first parent-DS
//	                     propagation wait); algo_old_ds_removal_wait,
//	                     algo_retiring → new only
//	No rollover:         active KSK only
func IncludesOldDS(r *statepkg.RolloverState) bool {
	if r == nil {
		return false
	}
	switch r.Type {
	case "ksk":
		return r.State == statepkg.KSKRolloverStateDSAddWait
	case "algorithm":
		return r.State == statepkg.AlgoRolloverStateDSAddWait || r.State == statepkg.AlgoRolloverStateDSPropagation
	}
	return false
}

// BuildDSSet computes the DS record set the registrar should hold for a zone
// in its CURRENT rollover phase (see IncludesOldDS): the active KSK always,
// plus the old KSK while its DS must remain at the parent.
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

	// While the rollover phase still requires it, include the old KSK's DS as
	// well — both DS records must be present at the parent so resolvers
	// mid-transition can validate either chain. Once the phase authorizes
	// old-DS removal the set is new-only, so neither automation nor an
	// explicit `registrar push` re-adds the old DS (RDAYBLUEX-007).
	if IncludesOldDS(zoneState.Rollover) {
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
