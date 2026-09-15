package main

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/fsutil"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
	"github.com/ptudor/sigillum-dnssec/signer/internal/validate"
	"github.com/spf13/cobra"
)

// `import` takes over a zone that another tool signed. This file is the CLI
// glue: it gathers the candidate keys (a directory scan, or two explicit
// pairs), asks the validator what the parent and the zone's own servers hold,
// has the signer package choose (signer.SelectImportKeys), shows the operator
// the inventory and the plan, and then runs the all-or-nothing transaction
// (RA6X-024): stage the keys and the complete signed zone, then activate,
// publish, record and register, undoing everything on any failure.

// newImportCmd builds the `import` command. Tests build the same command so
// the flag set they exercise is the one operators get.
func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import <domain> <zone-path>",
		Short: "Take over a zone signed by another tool, keeping its keys and DS",
		Long: `Take over a zone that another tool (dnssec-keygen/dnssec-signzone,
ldns-keygen/ldns-signzone, ...) signed, keeping the keys it uses so the DS
records at the parent stay valid and nothing changes for resolvers.

Point --keys-dir at the directory holding the other tool's key files:

  Kexample.com.+008+12345.key      Kexample.com.+008+12345.private
  Kexample.com.+008+67890.key      Kexample.com.+008+67890.private

Every pair for the zone is listed. Unless --offline is given, the parent's
DS records and the zone's authoritative servers are consulted, and the KSK
whose DS the parent holds and the ZSK that signs the served zone are chosen;
--ksk and --zsk (key tags) override the choice. --dry-run shows the inventory
and the plan without changing anything.

Without --keys-dir, --ksk and --zsk name the two key files directly, as paths
without the .key/.private extension.

Supported algorithms: ED25519, ECDSA P-256/P-384, RSASHA256 and RSASHA512.
Keys using SHA-1 (RSASHA1, RSASHA1-NSEC3-SHA1) are listed but refused, since
validating resolvers no longer treat SHA-1 signatures as secure.

The zone is signed with exactly the chosen keys, registered in the config
file and in state, and the DS record to verify at the parent is printed. The
DS is never pushed to a registrar by this command.`,
		Args: cobra.ExactArgs(2),
		RunE: runImport,
	}
	f := cmd.Flags()
	f.String("keys-dir", "", "Directory of BIND-style K<domain>.+<alg>+<tag>.{key,private} files to choose from")
	f.String("ksk", "", "KSK to import: a key tag (with --keys-dir) or a key file path without .key/.private")
	f.String("zsk", "", "ZSK to import: a key tag (with --keys-dir) or a key file path without .key/.private")
	f.Bool("offline", false, "Skip the parent DS and served-zone checks (the choice must then be unambiguous or explicit)")
	f.Bool("dry-run", false, "Show the keys found and the plan, then exit without changing anything")
	f.Bool("force", false, "Import even though the parent's DS records name a different KSK")
	return cmd
}

// importOptions are the parsed command flags.
type importOptions struct {
	keysDir string
	ksk     string
	zsk     string
	offline bool
	dryRun  bool
	force   bool
}

func importOptionsFromFlags(cmd *cobra.Command) (importOptions, error) {
	var o importOptions
	f := cmd.Flags()
	var err error
	if o.keysDir, err = f.GetString("keys-dir"); err != nil {
		return o, err
	}
	if o.ksk, err = f.GetString("ksk"); err != nil {
		return o, err
	}
	if o.zsk, err = f.GetString("zsk"); err != nil {
		return o, err
	}
	if o.offline, err = f.GetBool("offline"); err != nil {
		return o, err
	}
	if o.dryRun, err = f.GetBool("dry-run"); err != nil {
		return o, err
	}
	if o.force, err = f.GetBool("force"); err != nil {
		return o, err
	}
	if o.keysDir == "" && (o.ksk == "" || o.zsk == "") {
		return o, fmt.Errorf("pass --keys-dir <directory>, or both --ksk and --zsk as key file paths")
	}
	return o, nil
}

// runImport takes over a zone with keys from another signer.
func runImport(cmd *cobra.Command, args []string) error {
	domain := args[0]
	// Store an absolute path (see runAdd / R-017): a relative path recorded here
	// breaks once the daemon starts from a different working directory.
	zonePath, err := filepath.Abs(args[1])
	if err != nil {
		return fmt.Errorf("resolving zone path %q: %w", args[1], err)
	}
	if err := config.ValidateDomainName(domain); err != nil {
		return fmt.Errorf("invalid domain name: %w", err)
	}
	opts, err := importOptionsFromFlags(cmd)
	if err != nil {
		return err
	}

	cfg, state, unlock, err := loadConfigStateLocked()
	if err != nil {
		return err
	}
	defer unlock()

	// Check zone file exists
	if _, err := os.Stat(zonePath); os.IsNotExist(err) {
		return fmt.Errorf("zone file does not exist: %s", zonePath)
	}

	// Validate zone file
	if err := signerpkg.ValidateZoneFile(domain, zonePath); err != nil {
		return fmt.Errorf("invalid zone file: %w", err)
	}

	// Check domain not already managed
	if _, ok := cfg.Zones[domain]; ok {
		return fmt.Errorf("domain %q is already in config file", domain)
	}
	if state.GetZone(domain) != nil {
		return fmt.Errorf("domain %q is already managed (in state.json)", domain)
	}
	// R-029: reject a canonically-equivalent existing zone (case/trailing-dot only).
	if existing, dup := canonicalConflict(cfg, state, domain); dup {
		return fmt.Errorf("domain %q is the same DNS zone as already-managed %q (case/trailing-dot only); use the existing entry", domain, existing)
	}

	// Gather and describe every candidate pair, observe the zone as served
	// today, and choose. Nothing below this point writes anything until every
	// check on the imported material has passed (RA6X-024).
	cands, kskChoice, zskChoice, err := importCandidates(domain, opts)
	if err != nil {
		return err
	}
	obs, err := observeZoneForImport(cfg, state, domain, cands, opts.offline)
	if err != nil {
		return err
	}
	if opts.keysDir != "" {
		printImportInventory(os.Stdout, domain, opts.keysDir, cands, obs)
	}
	sel, err := signerpkg.SelectImportKeys(cands, obs, kskChoice, zskChoice)
	if err != nil {
		return fmt.Errorf("cannot choose the keys to import: %w", err)
	}
	printImportPlan(os.Stdout, domain, sel)
	if sel.DSMissing && !opts.force {
		return fmt.Errorf("refusing to import: the parent's DS records do not name KSK %d, so the signed zone would be bogus; pass --force only if you are changing the parent's DS to: %s",
			sel.KSK.Tag, sel.KSK.DNSKEY.ToDS(dns.SHA256).String())
	}
	if opts.dryRun {
		fmt.Println("Dry run: nothing was written.")
		return nil
	}
	ksk, kskPriv := sel.KSK.DNSKEY, sel.KSK.Private
	zsk, zskPriv := sel.ZSK.DNSKEY, sel.ZSK.Private

	slog.Info("[CLI] Importing keys for domain", "domain", domain, "ksk", sel.KSK.Base, "zsk", sel.ZSK.Base)

	// R-009: a mismatched-algorithm KSK/ZSK never reaches a live file. This
	// signer signs the DNSKEY RRset with the KSK algorithm and ordinary RRsets
	// with the ZSK algorithm only; if the two differ the published DNSKEY RRset
	// signals both while no RRset is signed with every algorithm — an
	// algorithm-incomplete zone that standards-conforming validators (RFC 6840
	// §5.11) may reject. The selection enforces this; the check stays as a
	// guard on the invariant.
	if ksk.Algorithm != zsk.Algorithm {
		return fmt.Errorf("refusing to import a KSK (%s) and ZSK (%s) with different algorithms: the result would be an algorithm-incomplete zone (RFC 6840 §5.11); import same-algorithm keys or use `rollover algorithm`",
			signerpkg.AlgorithmName(ksk.Algorithm), signerpkg.AlgorithmName(zsk.Algorithm))
	}

	// Preflight the config append before writing any key material (R-023, mirroring add):
	// fail now if the config file isn't writable, rather than after converting keys and
	// signing, which would leave state and config diverged with retry blocked.
	if err := preflightConfigAppend(configPath); err != nil {
		return fmt.Errorf("config file %s not writable (needed to register the imported zone): %w", configPath, err)
	}

	// Zone state and in-memory config for signing; the zone is not registered in
	// state until the commit step.
	now := time.Now().UTC()
	kskLifetime := cfg.GetZoneKSKLifetime(domain)
	zskLifetime := cfg.GetZoneZSKLifetime(domain)
	zoneState := &statepkg.ZoneState{
		Path: zonePath,
		KSK: &statepkg.KeyState{
			ID:          ksk.KeyTag(),
			Algorithm:   signerpkg.AlgorithmName(ksk.Algorithm),
			Created:     now, // Lifetimes count from the takeover, not the key's original creation.
			Expires:     now.Add(kskLifetime),
			RolloverDue: now.Add(time.Duration(float64(kskLifetime) * 0.75)),
		},
		ZSK: &statepkg.KeyState{
			ID:          zsk.KeyTag(),
			Algorithm:   signerpkg.AlgorithmName(zsk.Algorithm),
			Created:     now,
			Expires:     now.Add(zskLifetime),
			RolloverDue: now.Add(time.Duration(float64(zskLifetime) * 0.75)),
		},
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}

	keyGen := signerpkg.NewKeyGenerator(cfg)
	tx, err := beginImportTx(cfg, state, keyGen, domain)
	if err != nil {
		delete(cfg.Zones, domain)
		return err
	}

	// Stage: tag-named copies of both imported pairs (verified by reloading),
	// then the complete signed zone from exactly those keys, in a staging file.
	// The live key slots and the served output are untouched so far.
	if err = importFail("stage:ksk"); err == nil {
		_, err = keyGen.StageKeyPair(domain, "ksk", ksk, kskPriv)
	}
	if err != nil {
		return tx.fail(fmt.Errorf("staging KSK: %w", err))
	}
	if err = importFail("stage:zsk"); err == nil {
		_, err = keyGen.StageKeyPair(domain, "zsk", zsk, zskPriv)
	}
	if err != nil {
		return tx.fail(fmt.Errorf("staging ZSK: %w", err))
	}
	signer := signerpkg.NewSigner(cfg, state)
	if err := importFail("sign"); err != nil {
		return tx.fail(fmt.Errorf("signing zone: %w", err))
	}
	staged, err := signer.StageZoneWithKeys(domain, zoneState, ksk, kskPriv, zsk, zskPriv, tx.stagingPath())
	if err != nil {
		return tx.fail(fmt.Errorf("signing zone: %w", err))
	}
	tx.staged = staged

	// Commit, in an order every failure can undo: activate the live keys
	// (prior pairs preserved and restorable), publish the staged output over
	// the served one (prior bytes restorable), record the zone in state, then
	// register it in the config file.
	for _, role := range []string{"ksk", "zsk"} {
		tag := ksk.KeyTag()
		if role == "zsk" {
			tag = zsk.KeyTag()
		}
		if err = importFail("activate:" + role); err == nil {
			err = keyGen.ActivateKeyPair(domain, role, tag)
		}
		if err != nil {
			return tx.fail(fmt.Errorf("activating imported %s: %w", strings.ToUpper(role), err))
		}
		tx.activated = append(tx.activated, role)
		tx.tags[role] = tag
	}
	if err = importFail("publish"); err == nil {
		err = staged.Publish()
	}
	if err != nil {
		return tx.fail(fmt.Errorf("publishing signed zone: %w", err))
	}
	tx.published = true

	state.ClearRemoved(domain)
	state.SetZone(domain, zoneState)
	if err = importFail("save"); err == nil {
		err = persistState(state)
	}
	if err != nil {
		return tx.fail(fmt.Errorf("saving state: %w", err))
	}
	tx.stateSaved = true

	if err = importFail("config"); err == nil {
		err = commitConfigEdit(config.AddZoneToConfigFile(configPath, domain, zonePath))
	}
	if err != nil {
		return tx.fail(fmt.Errorf("adding zone to config file: %w", err))
	}

	// The import is fully committed from here (keys, output, state, config);
	// deployment runs before the summary so the summary can report it
	// truthfully, and a failed hook is reported through the exit status
	// (RDAYBLUEX-031) without rolling anything back.
	served, deployErr := runPostSignHook(cfg, state, domain, zonePath)

	fmt.Printf("\nDomain %s imported.\n", domain)
	fmt.Printf("  KSK: %s\n", describeImportKey(sel.KSK))
	fmt.Printf("  ZSK: %s\n", describeImportKey(sel.ZSK))
	fmt.Printf("  Config updated: %s\n", configPath)
	fmt.Printf("  Signed zone:    %s\n\n", signer.OutputPath(domain))
	switch {
	case obs.ParentProbed && obs.DSPresentOnAll[ksk.KeyTag()]:
		fmt.Println("DS record (confirmed at every parent server):")
	default:
		fmt.Println("DS record (verify this matches what's at your registrar):")
	}
	fmt.Println(signerpkg.FormatDSRecordsFromKey(domain, ksk))
	fmt.Println("Note: a running daemon picks up the new zone after SIGHUP (config reload).")

	return reportDeployment(domain, served, deployErr)
}

// importCandidates describes the key pairs the import may choose from and the
// operator's explicit choices, from either a --keys-dir scan or two explicit
// key file paths.
func importCandidates(domain string, opts importOptions) (cands []*signerpkg.ImportCandidate, ksk, zsk signerpkg.TagChoice, err error) {
	if opts.keysDir == "" {
		k := signerpkg.DescribeCandidate(domain, opts.ksk)
		z := signerpkg.DescribeCandidate(domain, opts.zsk)
		for _, c := range []*signerpkg.ImportCandidate{k, z} {
			if c.DNSKEY == nil {
				return nil, ksk, zsk, fmt.Errorf("%s", c.Problem)
			}
		}
		return []*signerpkg.ImportCandidate{k, z},
			signerpkg.TagChoice{Set: true, Tag: k.Tag},
			signerpkg.TagChoice{Set: true, Tag: z.Tag}, nil
	}
	cands, err = signerpkg.ScanBindKeys(opts.keysDir, domain)
	if err != nil {
		return nil, ksk, zsk, err
	}
	if ksk, cands, err = resolveKeyFlag(domain, "ksk", opts.ksk, cands); err != nil {
		return nil, ksk, zsk, err
	}
	if zsk, cands, err = resolveKeyFlag(domain, "zsk", opts.zsk, cands); err != nil {
		return nil, ksk, zsk, err
	}
	if len(cands) == 0 {
		return nil, ksk, zsk, fmt.Errorf("no K%s.+<alg>+<tag>.key/.private pairs found in %s", domain, opts.keysDir)
	}
	return cands, ksk, zsk, nil
}

// resolveKeyFlag interprets --ksk/--zsk alongside --keys-dir: empty means
// automatic, a number is a key tag among the scanned keys, and anything else
// is a key file path whose pair joins the candidates.
func resolveKeyFlag(domain, role, value string, cands []*signerpkg.ImportCandidate) (signerpkg.TagChoice, []*signerpkg.ImportCandidate, error) {
	if value == "" {
		return signerpkg.TagChoice{}, cands, nil
	}
	if tag, err := strconv.ParseUint(value, 10, 16); err == nil {
		return signerpkg.TagChoice{Set: true, Tag: uint16(tag)}, cands, nil
	}
	c := signerpkg.DescribeCandidate(domain, value)
	if c.DNSKEY == nil {
		return signerpkg.TagChoice{}, nil, fmt.Errorf("--%s %s: %s", role, value, c.Problem)
	}
	choice := signerpkg.TagChoice{Set: true, Tag: c.Tag}
	want, _ := filepath.Abs(c.Base)
	for _, existing := range cands {
		if have, _ := filepath.Abs(existing.Base); have == want {
			return choice, cands, nil
		}
	}
	return choice, append(cands, c), nil
}

// observeZoneForImport consults the parent's servers for the zone's DS and
// the zone's own servers for what they serve. The parent probe must succeed
// (or be skipped with --offline): a takeover that cannot see the DS it must
// keep valid is a guess. The served-zone probe only informs the choice, so
// its failure is reported and the import goes on.
func observeZoneForImport(cfg *config.Config, state *statepkg.State, domain string, cands []*signerpkg.ImportCandidate, offline bool) (signerpkg.ImportObservation, error) {
	var obs signerpkg.ImportObservation
	if offline {
		return obs, nil
	}
	timeout := cfg.Validation.Timeout.Duration
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	v := validate.NewValidator(cfg, state, cfg.Validation.Resolver, timeout)
	var ksks []*dns.DNSKEY
	for _, c := range cands {
		// Unusable KSKs are probed too, so a parent DS that names one of
		// them can be explained rather than merely reported as unmatched.
		if c.Role == "ksk" && c.DNSKEY != nil {
			ksks = append(ksks, c.DNSKEY)
		}
	}
	parent, err := v.ProbeParentDS(domain, ksks)
	if err != nil {
		return obs, fmt.Errorf("could not check the DS records at the parent of %s: %w (fix this, or pass --offline to import without checking)", domain, err)
	}
	obs.ParentProbed = true
	obs.ParentDS = parent.DSRecords
	obs.DSPresentOnAll = parent.PresentOnAll
	obs.DSAbsentOnAll = parent.AbsentOnAll

	served, err := v.ProbeServedKeys(domain)
	if err != nil {
		slog.Warn("[CLI] Import: could not consult the zone's authoritative servers", "domain", domain, "error", err)
		obs.ServedError = err.Error()
		return obs, nil
	}
	obs.ServedProbed = true
	obs.Served = served
	return obs, nil
}

// printImportInventory lists every key pair found and what the network said
// about each, followed by the reason any of them cannot be used.
func printImportInventory(w io.Writer, domain, dir string, cands []*signerpkg.ImportCandidate, obs signerpkg.ImportObservation) {
	fmt.Fprintf(w, "Keys for %s in %s:\n", domain, dir)
	tw := tabwriter.NewWriter(w, 2, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "  TAG\tROLE\tALGORITHM\tBITS\tCREATED\tPARENT DS\tSERVED\tSTATUS")
	var problems []string
	for _, c := range cands {
		role := strings.ToUpper(c.Role)
		if role == "" {
			role = "?"
		}
		bits := "-"
		if c.Bits > 0 {
			bits = strconv.Itoa(c.Bits)
		}
		created := "-"
		if !c.Created.IsZero() {
			created = c.Created.Format("2006-01-02")
		}
		status := "ok"
		if !c.Usable() {
			status = "unusable"
			problems = append(problems, fmt.Sprintf("  %s: %s", c.Name(), c.Problem))
		}
		fmt.Fprintf(tw, "  %d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			c.Tag, role, signerpkg.AlgorithmName(c.Algorithm), bits, created, parentDSColumn(c, obs), servedColumn(c, obs), status)
	}
	tw.Flush()
	for _, p := range problems {
		fmt.Fprintln(w, p)
	}
	switch {
	case obs.ParentProbed:
		fmt.Fprintf(w, "  Parent: %s\n", signerpkg.DescribeDS(obs.ParentDS))
	default:
		fmt.Fprintln(w, "  Parent: not checked")
	}
	switch {
	case obs.ServedProbed:
		s := obs.Served
		var tags []string
		for _, k := range s.DNSKEYs {
			tags = append(tags, strconv.Itoa(int(k.KeyTag())))
		}
		if len(tags) == 0 {
			fmt.Fprintf(w, "  Served (%d servers): no DNSKEY RRset\n", len(s.Servers))
		} else {
			fmt.Fprintf(w, "  Served (%d servers): DNSKEY %s (TTL %ds); SOA signed by %s; DNSKEY signed by %s",
				len(s.Servers), strings.Join(tags, ", "), s.DNSKEYTTL, tagsOrNone(s.SOASigners), tagsOrNone(s.DNSKEYSigners))
			if s.StaleSignatures {
				fmt.Fprint(w, "; every signature is expired")
			}
			fmt.Fprintln(w)
		}
	case obs.ServedError != "":
		fmt.Fprintf(w, "  Served: not observed (%s)\n", obs.ServedError)
	default:
		fmt.Fprintln(w, "  Served: not checked")
	}
	fmt.Fprintln(w)
}

func parentDSColumn(c *signerpkg.ImportCandidate, obs signerpkg.ImportObservation) string {
	switch {
	case c.Role != "ksk" || c.DNSKEY == nil:
		return ""
	case !obs.ParentProbed:
		return "-"
	case obs.DSPresentOnAll[c.Tag]:
		return "present"
	case obs.DSAbsentOnAll[c.Tag]:
		return "absent"
	}
	return "partial"
}

func servedColumn(c *signerpkg.ImportCandidate, obs signerpkg.ImportObservation) string {
	if c.DNSKEY == nil {
		return ""
	}
	if !obs.ServedProbed {
		return "-"
	}
	signers := obs.Served.SOASigners
	if c.Role == "ksk" {
		signers = obs.Served.DNSKEYSigners
	}
	for _, t := range signers {
		if t == c.Tag {
			return "signing"
		}
	}
	if obs.Served.Published(c.DNSKEY) {
		return "published"
	}
	return "no"
}

func tagsOrNone(tags []uint16) string {
	if len(tags) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(tags))
	for _, t := range tags {
		parts = append(parts, strconv.Itoa(int(t)))
	}
	return strings.Join(parts, ", ")
}

// printImportPlan shows the chosen pair, why, and what to read first.
func printImportPlan(w io.Writer, domain string, sel *signerpkg.ImportSelection) {
	fmt.Fprintf(w, "Plan for %s:\n", domain)
	fmt.Fprintf(w, "  KSK %s: %s\n", describeImportKey(sel.KSK), sel.KSKReason)
	fmt.Fprintf(w, "  ZSK %s: %s\n", describeImportKey(sel.ZSK), sel.ZSKReason)
	if len(sel.Warnings) > 0 {
		fmt.Fprintln(w, "Warnings:")
		for _, warning := range sel.Warnings {
			fmt.Fprintf(w, "  - %s\n", warning)
		}
	}
	fmt.Fprintln(w)
}

func describeImportKey(c *signerpkg.ImportCandidate) string {
	if c.Bits > 0 {
		return fmt.Sprintf("%d (%s, %d bits)", c.Tag, signerpkg.AlgorithmName(c.Algorithm), c.Bits)
	}
	return fmt.Sprintf("%d (%s)", c.Tag, signerpkg.AlgorithmName(c.Algorithm))
}

// importFailpoint is a test-only fault-injection seam consulted at each
// import transaction boundary; nil in production.
var importFailpoint func(step string) error

func importFail(step string) error {
	if importFailpoint == nil {
		return nil
	}
	return importFailpoint(step)
}

// priorFile is a snapshot of an artifact an import may replace, so a failed
// transaction restores its exact bytes and mode.
type priorFile struct {
	path    string
	data    []byte
	mode    os.FileMode
	existed bool
}

func snapshotFile(path string) (*priorFile, error) {
	pf := &priorFile{path: path}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return pf, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspecting %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s for rollback: %w", path, err)
	}
	pf.data, pf.mode, pf.existed = data, info.Mode().Perm(), true
	return pf, nil
}

// restore puts the snapshot back: the exact prior bytes and mode, or removal
// of a file that did not exist before (callers apply the key rule first — see
// importTx.rollback).
func (pf *priorFile) restore() error {
	if pf.existed {
		if err := fsutil.WriteFileAtomicOwned(pf.path, pf.data, pf.mode); err != nil && !fsutil.IsCommitted(err) {
			return err
		}
		return nil
	}
	if err := os.Remove(pf.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// importTx records the prior artifacts an import may replace and which commit
// steps have run, so a failure at any step restores the exact prior state
// (RA6X-024): live key pairs, the served signed output, the zone's absence from
// state and its removal marker. Staged tag-named key copies are left in place
// (key material is never deleted; a retry reuses them).
type importTx struct {
	cfg        *config.Config
	state      *statepkg.State
	keyGen     *signerpkg.KeyGenerator
	domain     string
	priorKeys  map[string][2]*priorFile // role → {.key, .private}
	priorOut   *priorFile
	removedAt  time.Time
	wasRemoved bool
	staged     *signerpkg.StagedZone
	activated  []string
	tags       map[string]uint16 // role → key tag activated there
	published  bool
	stateSaved bool
}

func beginImportTx(cfg *config.Config, state *statepkg.State, keyGen *signerpkg.KeyGenerator, domain string) (*importTx, error) {
	tx := &importTx{cfg: cfg, state: state, keyGen: keyGen, domain: domain, priorKeys: map[string][2]*priorFile{}, tags: map[string]uint16{}}
	keysDir := cfg.KeysDir()
	for _, role := range []string{"ksk", "zsk"} {
		base := filepath.Join(keysDir, domain+"."+role)
		k, err := snapshotFile(base + ".key")
		if err != nil {
			return nil, err
		}
		p, err := snapshotFile(base + ".private")
		if err != nil {
			return nil, err
		}
		tx.priorKeys[role] = [2]*priorFile{k, p}
	}
	out, err := snapshotFile(filepath.Join(cfg.OutputDir, domain+".zone.signed"))
	if err != nil {
		return nil, err
	}
	tx.priorOut = out
	tx.removedAt, tx.wasRemoved = state.RemovedAt(domain)
	if err := signerpkg.EnsureDir(cfg.OutputDir); err != nil {
		return nil, err
	}
	return tx, nil
}

// stagingPath is the staged signed zone: a dotfile beside the output so the
// final publish is a same-directory rename.
func (tx *importTx) stagingPath() string {
	return filepath.Join(tx.cfg.OutputDir, "."+tx.domain+".zone.signed.import")
}

// fail rolls the transaction back and returns the causing error, annotated
// with anything that could not be restored.
func (tx *importTx) fail(cause error) error {
	problems := tx.rollback()
	if len(problems) == 0 {
		return cause
	}
	return fmt.Errorf("%w (rollback incomplete: %s)", cause, strings.Join(problems, "; "))
}

func (tx *importTx) rollback() []string {
	var problems []string
	note := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		slog.Error("[CLI] Import rollback: "+msg, "domain", tx.domain)
		problems = append(problems, msg)
	}

	delete(tx.cfg.Zones, tx.domain)

	// State: undo the registration, restore the removal marker, and persist the
	// undo only if the registration itself was persisted.
	tx.state.RemoveZone(tx.domain)
	if tx.wasRemoved {
		tx.state.RestoreRemoved(tx.domain, tx.removedAt)
	}
	if tx.stateSaved {
		if err := persistState(tx.state); err != nil {
			note("could not remove the zone from state.json (%v); run `sigillum-signer remove %s` before retrying", err, tx.domain)
		}
	}

	// Output: the exact prior bytes, or nothing if there were none. A file that
	// existed before the import is never deleted.
	if tx.published {
		if err := tx.priorOut.restore(); err != nil {
			note("could not restore the previous signed output %s: %v", tx.priorOut.path, err)
		}
	} else if tx.staged != nil {
		tx.staged.Discard()
	}

	// Live keys: the exact prior pair for every activated role. A slot that was
	// empty before is emptied again only when its halves are byte-identical to
	// the staged tag-named copies, so no key material is ever lost.
	for _, role := range tx.activated {
		pair := tx.priorKeys[role]
		for i, pf := range pair {
			if pf.existed {
				if err := pf.restore(); err != nil {
					note("could not restore the previous %s key file %s: %v", role, pf.path, err)
				}
				continue
			}
			ext := ".key"
			if i == 1 {
				ext = ".private"
			}
			if !tx.liveMatchesStaged(role, ext) {
				note("left %s in place: it does not match the staged copy", pf.path)
				continue
			}
			if err := os.Remove(pf.path); err != nil && !os.IsNotExist(err) {
				note("could not remove %s: %v", pf.path, err)
			}
		}
	}
	if len(tx.activated) > 0 {
		fmt.Fprintf(os.Stderr, "note: staged copies of the imported keys were left in %s (a registrar DS may reference them); a retry reuses them\n", tx.cfg.KeysDir())
	}
	return problems
}

// liveMatchesStaged reports whether the live half for role is byte-identical to
// the tag-named staged copy of the key the import activated there.
func (tx *importTx) liveMatchesStaged(role, ext string) bool {
	live := filepath.Join(tx.cfg.KeysDir(), tx.domain+"."+role+ext)
	liveData, err := os.ReadFile(live)
	if err != nil {
		return os.IsNotExist(err)
	}
	staged := filepath.Join(tx.cfg.KeysDir(), fmt.Sprintf("%s.%s.%d%s", tx.domain, role, tx.tags[role], ext))
	stagedData, err := os.ReadFile(staged)
	if err != nil {
		return false
	}
	return bytes.Equal(liveData, stagedData)
}
