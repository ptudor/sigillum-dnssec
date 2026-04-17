package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// registrarContext returns a short-lived context for a single API call.
// The underlying http.Client already enforces a timeout; this ctx is
// primarily a cancellation channel for graceful shutdown.
func registrarContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// resolveRegistrar is a small helper used by all `registrar *` commands. It
// loads config + state, ensures the zone is managed, and returns the
// adapter. A missing adapter (no registrar configured for the zone) is an
// error in this context — the user explicitly asked for a registrar op.
func resolveRegistrar(domain string) (*Config, *State, Registrar, error) {
	cfg, state, err := loadConfigAndState()
	if err != nil {
		return nil, nil, nil, err
	}
	if state.GetZone(domain) == nil {
		return nil, nil, nil, fmt.Errorf("domain %q is not managed", domain)
	}
	reg, err := RegistrarFor(cfg, domain)
	if err != nil {
		return nil, nil, nil, err
	}
	if reg == nil {
		return nil, nil, nil, fmt.Errorf("zone %q has no registrar configured (set zones.%q.registrar in config)", domain, domain)
	}
	return cfg, state, reg, nil
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

	switch {
	case len(missing) == 0 && len(extra) == 0:
		slog.Info("[REGISTRAR] DS records already in sync", "domain", domain, "registrar", reg.Name())
		fmt.Printf("DS records at %s are already in sync with %s — nothing to do.\n", reg.Name(), domain)
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
			return fmt.Errorf("registrar replace_ds: %w", err)
		}
		fmt.Printf("Replaced DS record set at %s for %s (%d removed, %d installed).\n",
			reg.Name(), domain, len(extra), len(want))
	}
	return nil
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
	_, _, reg, err := resolveRegistrar(domain)
	if err != nil {
		return err
	}
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
func maybeAutoPublishDS(cfg *Config, state *State, domain string, op string) {
	reg, err := RegistrarFor(cfg, domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: registrar lookup failed: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "warning: cannot build DS set for auto-publish: %v\n", err)
		return
	}

	ctx, cancel := registrarContext()
	defer cancel()

	switch op {
	case "add", "rollover_complete":
		// Desired end-state is the full set — use ReplaceDS so the registrar
		// ends up with exactly what we want (no stale DS from prior configs).
		slog.Info("[REGISTRAR] auto-publishing DS (replace)", "domain", domain, "registrar", reg.Name(), "op", op)
		if err := reg.ReplaceDS(ctx, domain, want); err != nil {
			fmt.Fprintf(os.Stderr, "warning: registrar auto-publish failed: %v\n", err)
			return
		}
	case "rollover_start":
		// Only add the new KSK's DS — leave any existing DS records alone so
		// the old KSK's DS stays in place during the rollover window.
		slog.Info("[REGISTRAR] auto-publishing DS (additive)", "domain", domain, "registrar", reg.Name(), "op", op)
		if err := reg.AddDS(ctx, domain, want); err != nil {
			fmt.Fprintf(os.Stderr, "warning: registrar auto-publish failed: %v\n", err)
			return
		}
	default:
		fmt.Fprintf(os.Stderr, "warning: unknown auto-publish op %q; skipping\n", op)
		return
	}
	fmt.Printf("DS records published at %s for %s.\n", reg.Name(), domain)
}

// registrarAutoPublish returns the auto_publish flag for the named adapter.
func registrarAutoPublish(cfg *Config, name string) bool {
	switch strings.ToLower(name) {
	case "dynadot":
		return cfg.Registrar.Dynadot.AutoPublish
	}
	return false
}
