package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
	"github.com/spf13/cobra"
)

// recordRegistrarWarning attaches a warning to the zone's status (deduped) and
// persists state, so `dnssec-tudor status` and the dashboard reflect a
// registrar auto-publish failure that the operator would otherwise only see on
// stderr — honoring the documented "added to the zone's warnings array"
// contract (R-032). Mutation and Save each take the state write lock
// separately (Mutate's fn must not re-enter State methods).
func recordRegistrarWarning(state *statepkg.State, domain, msg string) {
	state.UpdateZone(domain, func(z *statepkg.ZoneState) { z.AddWarning(msg) })
	if err := state.Save(); err != nil {
		slog.Error("[REGISTRAR] failed to persist zone warning", "domain", domain, "warning", msg, "error", err)
	}
}

// registrarContext returns a short-lived context for a single API call.
// The underlying http.Client already enforces a timeout; this ctx is
// primarily a cancellation channel for graceful shutdown.
func registrarContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// resolveRegistrar is a small helper used by the read-only `registrar *`
// commands (get, verify). It loads config + state WITHOUT the cross-process
// state lock — these commands never Save — ensures the zone is managed, and
// returns the adapter. A missing adapter (no registrar configured for the
// zone) is an error in this context — the user explicitly asked for a
// registrar op.
func resolveRegistrar(domain string) (*config.Config, *statepkg.State, Registrar, error) {
	cfg, state, err := loadConfigAndState()
	if err != nil {
		return nil, nil, nil, err
	}
	reg, err := registrarForManagedZone(cfg, state, domain)
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, state, reg, nil
}

// resolveRegistrarLocked is the mutating-command variant of resolveRegistrar,
// used by `registrar push` and `registrar clear`: it loads state under the
// cross-process state lock (R-007) and returns the unlock func for the caller
// to defer. push persists registrar state (zone warnings) via state.Save() —
// saving a snapshot loaded outside the lock can clobber a concurrent
// daemon/CLI write, and the daemon's fresher-LastSigned merge then drops the
// URGENT zero-DS warning (R-032); clear's destructive DS wipe must likewise
// not interleave with a concurrent locked auto-publish. The lock is
// deliberately held across the registrar network calls — the same accepted
// pattern as maybeAutoPublishDS running under its caller's lock — with the
// usual 30s acquisition timeout.
func resolveRegistrarLocked(domain string) (*config.Config, *statepkg.State, Registrar, func(), error) {
	cfg, state, unlock, err := loadConfigStateLocked()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	reg, err := registrarForManagedZone(cfg, state, domain)
	if err != nil {
		unlock()
		return nil, nil, nil, nil, err
	}
	return cfg, state, reg, unlock, nil
}

// registrarForManagedZone is the shared back half of resolveRegistrar and
// resolveRegistrarLocked: it ensures the zone is managed and resolves its
// configured registrar adapter.
func registrarForManagedZone(cfg *config.Config, state *statepkg.State, domain string) (Registrar, error) {
	if state.GetZone(domain) == nil {
		return nil, fmt.Errorf("domain %q is not managed", domain)
	}
	reg, err := RegistrarFor(cfg, domain)
	if err != nil {
		return nil, err
	}
	if reg == nil {
		return nil, fmt.Errorf("zone %q has no registrar configured (set zones.%q.registrar in config)", domain, domain)
	}
	return reg, nil
}

// dsSummary is the JSON-friendly form of a DS record used by registrar CLI
// output. Using our own type keeps field names explicit and avoids dumping
// dns.DS internals that change by miekg/dns version.
type dsSummary struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digest_type"`
	Digest     string `json:"digest"`
	Record     string `json:"record"`
}

func toDSSummary(ds *dns.DS) dsSummary {
	return dsSummary{
		KeyTag:     ds.KeyTag,
		Algorithm:  ds.Algorithm,
		DigestType: ds.DigestType,
		Digest:     strings.ToUpper(ds.Digest),
		Record:     ds.String(),
	}
}

func summarizeDSList(list []*dns.DS) []dsSummary {
	out := make([]dsSummary, 0, len(list))
	for _, d := range list {
		out = append(out, toDSSummary(d))
	}
	return out
}

// runRegistrarGet prints the DS records currently at the registrar.
func runRegistrarGet(cmd *cobra.Command, args []string) error {
	domain := args[0]
	_, _, reg, err := resolveRegistrar(domain)
	if err != nil {
		return err
	}

	ctx, cancel := registrarContext()
	defer cancel()

	records, err := reg.GetDS(ctx, domain)
	if err != nil {
		return fmt.Errorf("registrar get_dnssec: %w", err)
	}

	out := map[string]any{
		"domain":    domain,
		"registrar": reg.Name(),
		"ds":        summarizeDSList(records),
	}
	return printJSON(out)
}

// runRegistrarPush ensures the registrar holds exactly the DS set that the
// signer expects. It computes the current vs desired diff and picks the
// least-disruptive operation: no-op if in sync, AddDS if only additions are
// needed, ReplaceDS if anything must be removed.
func runRegistrarPush(cmd *cobra.Command, args []string) error {
	domain := args[0]
	// Locked: the ErrRegistrarDSEmpty branch persists a zone warning, and that
	// Save must not run from a snapshot loaded outside the lock (R-032).
	cfg, state, reg, unlock, err := resolveRegistrarLocked(domain)
	if err != nil {
		return err
	}
	defer unlock()

	want, err := BuildDSSet(cfg, state, domain)
	if err != nil {
		return fmt.Errorf("building expected DS set: %w", err)
	}

	ctx, cancel := registrarContext()
	defer cancel()

	have, err := reg.GetDS(ctx, domain)
	if err != nil {
		return fmt.Errorf("registrar get_dnssec: %w", err)
	}

	missing, extra := CompareDSSets(want, have)

	switch {
	case len(missing) == 0 && len(extra) == 0:
		slog.Info("[REGISTRAR] DS records already in sync", "domain", domain, "registrar", reg.Name())
		fmt.Printf("DS records at %s are already in sync with %s — nothing to do.\n", reg.Name(), domain)
		clearRegistrarStickyWarnings(state, domain, want)
		return nil
	case len(extra) == 0:
		// Only additions needed — use additive call so any concurrent DS
		// record we don't track (unlikely but possible) isn't lost.
		if err := reg.AddDS(ctx, domain, missing); err != nil {
			return fmt.Errorf("registrar add_ds: %w", err)
		}
		fmt.Printf("Added %d DS record(s) at %s for %s.\n", len(missing), reg.Name(), domain)
	default:
		// Removals required — full replace is the only option supported by
		// Dynadot's clear+set API shape.
		slog.Warn("[REGISTRAR] replacing DS set — brief window with no DS at parent",
			"domain", domain, "removing", len(extra), "adding", len(missing))
		if err := reg.ReplaceDS(ctx, domain, want); err != nil {
			if errors.Is(err, ErrRegistrarDSEmpty) {
				// Restore failed after the DELETE: the parent now holds zero DS.
				// Persist a zone warning and log remediation in addition to the
				// non-zero exit, so status/dashboard surface the outage (R-004).
				slog.Error("[REGISTRAR] DS restore failed — parent left with ZERO DS; zone will go bogus until republished",
					"domain", domain, "registrar", reg.Name(),
					"remediation", fmt.Sprintf("re-run `dnssec-tudor registrar push %s`", domain),
					"error", err)
				recordRegistrarWarning(state, domain,
					fmt.Sprintf("URGENT: registrar left zone with ZERO DS at parent; re-run `dnssec-tudor registrar push %s`: %v", domain, err))
			}
			return fmt.Errorf("registrar replace_ds: %w", err)
		}
		fmt.Printf("Replaced DS record set at %s for %s (%d removed, %d installed).\n",
			reg.Name(), domain, len(extra), len(want))
	}
	clearRegistrarStickyWarnings(state, domain, want)
	return nil
}

// clearRegistrarStickyWarnings clears the registrar-critical (sticky) warnings for
// a zone once a push has left the expected NONEMPTY DS set at the parent — the
// read-back that confirms the zero-DS condition is resolved (R-017). It is a no-op
// when the expected DS set is empty or no sticky warning is present, and persists
// state only when it actually removed a warning.
func clearRegistrarStickyWarnings(state *statepkg.State, domain string, want []*dns.DS) {
	if len(want) == 0 {
		return
	}
	cleared := false
	state.UpdateZone(domain, func(z *statepkg.ZoneState) {
		before := len(z.Warnings)
		z.ClearStickyWarnings()
		cleared = len(z.Warnings) != before
	})
	if cleared {
		if err := state.Save(); err != nil {
			slog.Error("[REGISTRAR] failed to persist cleared warning after successful DS push",
				"domain", domain, "error", err)
		}
	}
}

// runRegistrarVerify prints the diff between expected and actual DS records.
// Exits non-zero on drift so cron jobs can detect misconfiguration.
func runRegistrarVerify(cmd *cobra.Command, args []string) error {
	domain := args[0]
	cfg, state, reg, err := resolveRegistrar(domain)
	if err != nil {
		return err
	}

	want, err := BuildDSSet(cfg, state, domain)
	if err != nil {
		return fmt.Errorf("building expected DS set: %w", err)
	}

	ctx, cancel := registrarContext()
	defer cancel()

	have, err := reg.GetDS(ctx, domain)
	if err != nil {
		return fmt.Errorf("registrar get_dnssec: %w", err)
	}

	missing, extra := CompareDSSets(want, have)

	out := map[string]any{
		"domain":    domain,
		"registrar": reg.Name(),
		"expected":  summarizeDSList(want),
		"actual":    summarizeDSList(have),
		"missing":   summarizeDSList(missing),
		"extra":     summarizeDSList(extra),
		"in_sync":   len(missing) == 0 && len(extra) == 0,
	}
	if err := printJSON(out); err != nil {
		return err
	}
	if len(missing) != 0 || len(extra) != 0 {
		os.Exit(1)
	}
	return nil
}

// runRegistrarClear wipes all DS records at the registrar. Useful when
// retiring DNSSEC on a zone or recovering from a bad push. We require the
// user to type the command on purpose (no confirmation prompt here), but we
// log loudly so the operator can find it in logs later.
func runRegistrarClear(cmd *cobra.Command, args []string) error {
	domain := args[0]
	// Locked: the DS wipe must not interleave with a concurrent locked
	// auto-publish or push for the same zone (R-007).
	_, _, reg, unlock, err := resolveRegistrarLocked(domain)
	if err != nil {
		return err
	}
	defer unlock()
	slog.Warn("[REGISTRAR] clearing all DS records", "domain", domain, "registrar", reg.Name())

	ctx, cancel := registrarContext()
	defer cancel()

	if err := reg.ReplaceDS(ctx, domain, nil); err != nil {
		return fmt.Errorf("registrar clear: %w", err)
	}
	fmt.Printf("All DS records cleared at %s for %s.\n", reg.Name(), domain)
	return nil
}

func printJSON(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling json: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// maybeAutoPublishDS is called from runAdd / runRollover* commands when the
// operator has enabled auto_publish on the configured registrar. Failures
// are surfaced to the user as warnings but never turned into command errors
// — the signer's source-of-truth work (signing) already succeeded, and the
// operator can retry via `registrar push`.
func maybeAutoPublishDS(cfg *config.Config, state *statepkg.State, domain string, op string) {
	reg, err := RegistrarFor(cfg, domain)
	if err != nil {
		msg := fmt.Sprintf("registrar auto-publish failed: registrar lookup failed: %v", err)
		fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
		recordRegistrarWarning(state, domain, msg)
		return
	}
	if reg == nil {
		return
	}
	if !registrarAutoPublish(cfg, reg.Name()) {
		fmt.Printf("Registrar %s is configured but auto_publish is off; run `dnssec-tudor registrar push %s` to publish DS.\n", reg.Name(), domain)
		return
	}

	want, err := BuildDSSet(cfg, state, domain)
	if err != nil {
		msg := fmt.Sprintf("registrar auto-publish failed: cannot build DS set: %v", err)
		fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
		recordRegistrarWarning(state, domain, msg)
		return
	}

	ctx, cancel := registrarContext()
	defer cancel()

	switch op {
	case "add", "rollover_start":
		// Additive publish. For `add`, this avoids the failure mode where a
		// destructive ReplaceDS clears valid DS at the registrar before the
		// PUT lands — leaving a zone with no DS at all, which validators
		// read as an unsigned delegation (silent DNSSEC outage). Operators
		// can clear residual DS explicitly via `dnssec-tudor registrar push`
		// or `... registrar clear` after verifying with `... registrar verify`.
		// For `rollover_start`, additive is required so the old KSK's DS
		// stays published throughout the rollover window.
		slog.Info("[REGISTRAR] auto-publishing DS (additive)", "domain", domain, "registrar", reg.Name(), "op", op)
		if err := reg.AddDS(ctx, domain, want); err != nil {
			msg := fmt.Sprintf("registrar auto-publish failed: %v", err)
			fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
			recordRegistrarWarning(state, domain, msg)
			return
		}
	case "rollover_complete":
		// Rollover finalization: remove the old KSK's DS and leave only the
		// new one. ReplaceDS is PUT-first internally, so a publish failure
		// aborts before any destructive DELETE — except a transient failure of
		// the post-DELETE restore, which strands the zone with zero DS at the
		// parent (ErrRegistrarDSEmpty). Escalate that case to Error with
		// remediation, since the zone is actively going bogus (R-004 + R-032).
		slog.Info("[REGISTRAR] auto-publishing DS (replace)", "domain", domain, "registrar", reg.Name(), "op", op)
		if err := reg.ReplaceDS(ctx, domain, want); err != nil {
			if errors.Is(err, ErrRegistrarDSEmpty) {
				slog.Error("[REGISTRAR] DS restore failed — parent left with ZERO DS; zone will go bogus until republished",
					"domain", domain, "registrar", reg.Name(),
					"remediation", fmt.Sprintf("run `dnssec-tudor registrar push %s` to republish the DS set immediately", domain),
					"error", err)
				recordRegistrarWarning(state, domain,
					fmt.Sprintf("URGENT: registrar left zone with ZERO DS at parent; run `dnssec-tudor registrar push %s` immediately: %v", domain, err))
			} else {
				msg := fmt.Sprintf("registrar auto-publish failed: %v", err)
				fmt.Fprintf(os.Stderr, "warning: %s\n", msg)
				recordRegistrarWarning(state, domain, msg)
			}
			return
		}
	default:
		fmt.Fprintf(os.Stderr, "warning: unknown auto-publish op %q; skipping\n", op)
		return
	}
	fmt.Printf("DS records published at %s for %s.\n", reg.Name(), domain)
}

// registrarAutoPublish returns the auto_publish flag for the named adapter.
func registrarAutoPublish(cfg *config.Config, name string) bool {
	switch strings.ToLower(name) {
	case "dynadot":
		return cfg.Registrar.Dynadot.AutoPublish
	}
	return false
}
