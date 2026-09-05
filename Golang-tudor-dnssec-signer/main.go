package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ptudor/dnssec-tudor/internal/validate"

	"github.com/ptudor/dnssec-tudor/internal/registrar"

	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
	"github.com/ptudor/dnssec-tudor/internal/fsutil"
	"github.com/spf13/cobra"
)

// Version and build info, set by ldflags
var (
	Version   = "dev"
	BuildTime = "unknown"
)

var (
	configPath string
	logLevel   string
	logFormat  string
	logOutput  string

	// logFile tracks the current log file handle so it can be closed on reload
	logFile *os.File

	// syslogCloser tracks the current syslog connection so it can be closed on
	// reload — setupLogging is re-run on SIGHUP (R-056), and re-dialing syslog
	// without closing the previous writer leaks one fd per reload.
	syslogCloser io.Closer
)

func main() {
	// Propagate the ldflags-injected build version into the registrar package
	// so its Dynadot adapter's default User-Agent reports the real build.
	registrar.Version = Version

	// Root command
	rootCmd := &cobra.Command{
		Use:   "dnssec-tudor",
		Short: "A minimal DNSSEC signing daemon",
		Long: `dnssec-tudor is a minimal, opinionated DNSSEC signing daemon for sysadmins
who just want zones signed without the complexity of full-featured solutions.

It watches unsigned zone files, generates keys, signs zones automatically,
and outputs signed zones for authoritative nameservers like NSD.`,
		// Don't dump the full usage text on an operational error (e.g. "zone not
		// managed") — that buries the real error. Cobra still prints the error
		// itself (SilenceErrors stays false, and main relies on that), just not
		// the usage (R-059).
		SilenceUsage: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			setupLogging()
		},
	}

	// Persistent flags
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/dnssec-tudor/config.toml", "Path to config file")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", getEnvOrDefault("LOG_LEVEL", "info"), "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", getEnvOrDefault("LOG_FORMAT", "text"), "Log format (text, json)")
	rootCmd.PersistentFlags().StringVar(&logOutput, "log-output", getEnvOrDefault("LOG_OUTPUT", "stderr"), "Log output (stderr, syslog, or file path)")

	// version command
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("dnssec-tudor %s (built %s)\n", Version, BuildTime)
		},
	}

	// serve command
	var webAddr string
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Run as a daemon, watching for zone changes",
		RunE:  runServe,
	}
	serveCmd.Flags().StringVar(&webAddr, "web", "", "Enable web UI on address (e.g., :8053)")

	// sign command
	signCmd := &cobra.Command{
		Use:   "sign",
		Short: "One-shot: sign all zones and exit",
		RunE:  runSign,
	}

	// resign command (force re-sign a specific domain)
	resignCmd := &cobra.Command{
		Use:   "resign <domain>",
		Short: "Force re-sign a specific domain (bypasses change detection)",
		Args:  cobra.ExactArgs(1),
		RunE:  runResign,
	}

	// status command
	var statusDomain string
	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Print status JSON to stdout",
		RunE:  runStatus,
	}
	statusCmd.Flags().StringVarP(&statusDomain, "domain", "d", "", "Show status for specific domain only")
	statusCmd.Flags().Bool("validate", false, "Include internet DNSSEC validation in status output")

	// validate command
	validateCmd := &cobra.Command{
		Use:   "validate [domain]",
		Short: "Check DNSSEC visibility on the internet",
		Long: `Queries the internet to verify DS records at parent, DNSKEY/RRSIG
visibility at authoritative nameservers, and SOA serial consistency.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runValidate,
	}
	validateCmd.Flags().String("resolver", "", "Recursive resolver (default: system resolver)")

	// add command
	addCmd := &cobra.Command{
		Use:   "add <domain> <zone-path>",
		Short: "Add a new domain to manage",
		Args:  cobra.ExactArgs(2),
		RunE:  runAdd,
	}

	// remove command
	removeCmd := &cobra.Command{
		Use:   "remove <domain>",
		Short: "Remove a domain from management (does not delete keys)",
		Args:  cobra.ExactArgs(1),
		RunE:  runRemove,
	}

	// rollover command
	rolloverCmd := &cobra.Command{
		Use:   "rollover",
		Short: "Key rollover commands",
	}

	rolloverStartCmd := &cobra.Command{
		Use:   "start <domain>",
		Short: "Begin KSK rollover for a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  runRolloverStart,
	}

	rolloverStatusCmd := &cobra.Command{
		Use:   "status <domain>",
		Short: "Show rollover status for a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  runRolloverStatus,
	}

	rolloverCompleteCmd := &cobra.Command{
		Use:   "complete <domain>",
		Short: "Finalize KSK or algorithm rollover after DS update",
		Args:  cobra.ExactArgs(1),
		RunE:  runRolloverComplete,
	}
	// --force skips the parent-DS visibility check (R-037). Retiring the old KSK
	// before the new DS is live at the parent SERVFAILs the zone, so verification
	// is on by default.
	rolloverCompleteCmd.Flags().Bool("force", false, "complete even if the new KSK's DS is not yet visible at the parent (dangerous)")

	rolloverAlgorithmCmd := &cobra.Command{
		Use:   "algorithm <domain> <new-algorithm>",
		Short: "Start algorithm rollover (ED25519, ECDSAP256SHA256, ECDSAP384SHA384)",
		Args:  cobra.ExactArgs(2),
		RunE:  runRolloverAlgorithm,
	}

	rolloverCmd.AddCommand(rolloverStartCmd, rolloverStatusCmd, rolloverCompleteCmd, rolloverAlgorithmCmd)

	// ds command
	dsCmd := &cobra.Command{
		Use:   "ds <domain>",
		Short: "Print DS records for a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  runDS,
	}
	dsCmd.Flags().Bool("json", false, "Output in JSON format")

	// dnskey command
	dnskeyCmd := &cobra.Command{
		Use:   "dnskey <domain>",
		Short: "Print DNSKEY records for a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  runDNSKEY,
	}
	dnskeyCmd.Flags().Bool("json", false, "Output in JSON format")

	// registrar command group
	registrarCmd := &cobra.Command{
		Use:   "registrar",
		Short: "Interact with a configured registrar API (opt-in per zone)",
	}
	registrarGetCmd := &cobra.Command{
		Use:   "get <domain>",
		Short: "Show DS records currently published at the registrar",
		Args:  cobra.ExactArgs(1),
		RunE:  RunRegistrarGet,
	}
	registrarPushCmd := &cobra.Command{
		Use:   "push <domain>",
		Short: "Push expected DS records to the registrar (idempotent)",
		Args:  cobra.ExactArgs(1),
		RunE:  RunRegistrarPush,
	}
	registrarVerifyCmd := &cobra.Command{
		Use:   "verify <domain>",
		Short: "Compare expected vs published DS records (exit 1 on drift)",
		Args:  cobra.ExactArgs(1),
		RunE:  RunRegistrarVerify,
	}
	registrarClearCmd := &cobra.Command{
		Use:   "clear <domain>",
		Short: "Remove all DS records at the registrar",
		Args:  cobra.ExactArgs(1),
		RunE:  RunRegistrarClear,
	}
	registrarCmd.AddCommand(registrarGetCmd, registrarPushCmd, registrarVerifyCmd, registrarClearCmd)

	// import command
	var importKSK, importZSK string
	importCmd := &cobra.Command{
		Use:   "import <domain> <zone-path>",
		Short: "Import existing BIND-style DNSSEC keys",
		Long: `Import existing BIND-style DNSSEC keys for a domain.

Provide paths to the key files without the .key/.private extension.
For example, if your keys are:
  Kexample.com.+015+12345.key
  Kexample.com.+015+12345.private

Use: --ksk Kexample.com.+015+12345

The command will read both .key and .private files, convert them to
dnssec-tudor's format, and set up the zone for management.`,
		Args: cobra.ExactArgs(2),
		RunE: runImport,
	}
	importCmd.Flags().StringVar(&importKSK, "ksk", "", "Path to KSK key files (without .key/.private extension)")
	importCmd.Flags().StringVar(&importZSK, "zsk", "", "Path to ZSK key files (without .key/.private extension)")
	importCmd.MarkFlagRequired("ksk")
	importCmd.MarkFlagRequired("zsk")

	// Add all commands
	rootCmd.AddCommand(versionCmd, serveCmd, signCmd, resignCmd, statusCmd, validateCmd, addCmd, removeCmd, rolloverCmd, dsCmd, dnskeyCmd, importCmd, registrarCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func setupLogging() {
	var level slog.Level
	switch logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler

	switch logOutput {
	case "syslog":
		if !syslogSupported() {
			fmt.Fprintf(os.Stderr, "syslog not supported on this platform, falling back to stderr\n")
			handler = slog.NewTextHandler(os.Stderr, opts)
		} else {
			// Close the previous syslog connection before dialing a new one,
			// mirroring the logFile handling below — without this each SIGHUP
			// reload leaks one syslog fd.
			closeSyslogWriter()
			h, closer, err := newSyslogHandler(level)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to connect to syslog: %v, falling back to stderr\n", err)
				handler = slog.NewTextHandler(os.Stderr, opts)
			} else {
				handler = h
				syslogCloser = closer
			}
		}
	case "stderr", "":
		if logFormat == "json" {
			handler = slog.NewJSONHandler(os.Stderr, opts)
		} else {
			handler = slog.NewTextHandler(os.Stderr, opts)
		}
	default:
		// Treat as file path — close previous log file if open
		if logFile != nil {
			logFile.Close()
			logFile = nil
		}
		f, err := os.OpenFile(logOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open log file %s: %v, falling back to stderr\n", logOutput, err)
			handler = slog.NewTextHandler(os.Stderr, opts)
		} else {
			logFile = f
			if logFormat == "json" {
				handler = slog.NewJSONHandler(f, opts)
			} else {
				handler = slog.NewTextHandler(f, opts)
			}
		}
	}

	slog.SetDefault(slog.New(handler))
}

// closeSyslogWriter closes the syslog connection left over from a previous
// setupLogging run and clears the tracker. Nil-safe: fresh startup, non-syslog
// outputs, and platforms without syslog have nothing to close.
func closeSyslogWriter() {
	if syslogCloser == nil {
		return
	}
	syslogCloser.Close()
	syslogCloser = nil
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func loadConfigAndState() (*config.Config, *statepkg.State, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("loading config: %w", err)
	}

	// Capture the data_dir owner before any writes so CLI commands run as
	// root will chown what they create. No-op for non-root invocations. A
	// failed inspection is an error, not a silent no-op (RA6X-044).
	if _, err := fsutil.InitOwnershipTarget(cfg.DataDir); err != nil {
		return nil, nil, err
	}

	state, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		return nil, nil, fmt.Errorf("loading state: %w", err)
	}

	return cfg, state, nil
}

// loadConfigStateLocked loads config, acquires the cross-process state lock, then loads
// state UNDER the lock. Mutating CLI commands use this and `defer unlock()` so their whole
// load→mutate→Save span is serialized against the daemon's signing cycle and other CLI
// commands (R-007) — otherwise a rollover/add/remove landing mid-cycle is clobbered by the
// daemon's end-of-cycle Save. Read-only commands (status/ds/dnskey/validate/rollover
// status) keep loadConfigAndState and take no lock.
func loadConfigStateLocked() (cfg *config.Config, state *statepkg.State, unlock func(), err error) {
	cfg, err = config.LoadConfig(configPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading config: %w", err)
	}
	// A mutating command run as root must not create a root-owned tree the
	// daemon account cannot use; the operator bootstraps it explicitly
	// (RA6X-044). Root-only deployments create the directory as root first.
	if err := checkOwnershipBootstrap(cfg.DataDir); err != nil {
		return nil, nil, nil, err
	}
	if err := signerpkg.EnsureDir(cfg.DataDir); err != nil {
		return nil, nil, nil, fmt.Errorf("ensuring data_dir for state lock: %w", err)
	}
	lock, err := acquireStateLock(cfg.DataDir, 30*time.Second)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("acquiring state lock: %w", err)
	}
	state, err = statepkg.LoadState(cfg.StatePath())
	if err != nil {
		lock.release()
		return nil, nil, nil, fmt.Errorf("loading state: %w", err)
	}
	return cfg, state, lock.release, nil
}

// preflightConfigAppend verifies the config file can be opened for append.
// Used by `add` to fail fast before generating keys or signing a zone when
// the daemon user can't write to the config file.
func preflightConfigAppend(path string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

// runPostSignHook fires the configured post-sign hook synchronously for one
// zone a CLI command just signed, under the same contract the daemon uses
// (RA6X-043): a batch invocation naming the single domain when coalescing is
// on, the per-zone invocation otherwise. A successful hook confirms the
// generation as published and persists that (RA6X-004); a failure is logged,
// the zone stays pending (the daemon retries the deployment) and false is
// returned so callers can hold back steps that assume the zone is served.
// With no hook configured the signing result already counts as published.
func runPostSignHook(cfg *config.Config, state *statepkg.State, domain, zonePath string) bool {
	if !hookConfigured(&cfg.Hooks) {
		return true
	}
	zs := state.GetZone(domain)
	if zs == nil {
		return false
	}
	slog.Info("[CLI] Executing post-sign hook", "domain", domain)
	ref := signedRef(cfg, domain, zonePath, zs.LastSigned)
	if err := firePostSignHooks(&cfg.Hooks, cfg.OutputDir, []SignedZoneRef{ref}, nil, nil); err != nil {
		slog.Error("[CLI] Post-sign hook failed; the zone is not confirmed served and stays pending deployment", "domain", domain, "error", err)
		fmt.Fprintf(os.Stderr, "warning: post-sign hook failed for %s; the signed zone is written but not confirmed served (the daemon retries the hook)\n", domain)
		return false
	}
	confirmPublicationCLI(state, []SignedZoneRef{ref})
	return true
}

// confirmPublicationCLI records hook-confirmed publication for the given
// generations and persists the state (RA6X-004).
func confirmPublicationCLI(state *statepkg.State, zones []SignedZoneRef) {
	now := time.Now().UTC()
	for _, z := range zones {
		zs := state.GetZone(z.Domain)
		if zs == nil {
			continue
		}
		state.Mutate(func() { zs.ConfirmPublication(z.SignedAt, now) })
	}
	if err := persistState(state); err != nil {
		slog.Error("[CLI] Failed to persist publication confirmation; the daemon will re-run the hook", "error", err)
	}
}

// keyPairAbsent reports whether NEITHER half of a domain's key pair (role
// "ksk" or "zsk") exists in keysDir. runAdd uses it to decide whether a failed
// add may delete key files on rollback: generation can only have occurred when
// both halves were absent beforehand — RecoverOrGenerateKeys refuses to touch
// a half-present pair (R-028). Checking only the .key half would mark a
// .private-only orphan as "generated by this add" and let unwindAdd delete the
// sole surviving copy of a key whose DS may still be live at the parent.
func keyPairAbsent(keysDir, domain, role string) bool {
	return !signerpkg.FileExists(filepath.Join(keysDir, domain+"."+role+".key")) &&
		!signerpkg.FileExists(filepath.Join(keysDir, domain+"."+role+".private"))
}

// unwindAdd undoes the on-disk side effects of a partial `add`: removes the
// zone from in-memory state, persists state.json, and deletes the signed
// zone file. Key files are deleted only when this `add` generated them —
// keys recovered from a previous management period must survive the
// rollback, since a DS at the registrar may still reference them.
// Best-effort — failures are logged but not returned, so the original error
// from `add` surfaces unchanged.
func unwindAdd(cfg *config.Config, state *statepkg.State, domain string, removeKSK, removeZSK bool, origOutput []byte, outputExisted bool) {
	state.RemoveZone(domain)
	if err := persistState(state); err != nil {
		slog.Warn("[CLI] Rollback: failed to save state", "domain", domain, "error", err)
	}

	signedPath := filepath.Join(cfg.OutputDir, domain+".zone.signed")
	if outputExisted {
		// R-011: a signed output existed before this add (a re-add over a previous
		// management period). Restore the exact previous bytes — a nameserver may
		// still be serving them — rather than deleting the last known-good zone.
		if err := fsutil.WriteFileOwned(signedPath, origOutput, 0644); err != nil {
			slog.Warn("[CLI] Rollback: failed to restore previous signed zone", "path", signedPath, "error", err)
		}
	} else if err := os.Remove(signedPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("[CLI] Rollback: failed to remove signed zone", "path", signedPath, "error", err)
	}

	keysDir := cfg.KeysDir()
	var keyFiles []string
	if removeKSK {
		keyFiles = append(keyFiles,
			filepath.Join(keysDir, domain+".ksk.key"),
			filepath.Join(keysDir, domain+".ksk.private"))
	}
	if removeZSK {
		keyFiles = append(keyFiles,
			filepath.Join(keysDir, domain+".zsk.key"),
			filepath.Join(keysDir, domain+".zsk.private"))
	}
	for _, p := range keyFiles {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			slog.Warn("[CLI] Rollback: failed to remove key file", "path", p, "error", err)
		}
	}
}

// runServe runs the daemon
// loadStateLocked loads the state file under the cross-process state lock so
// the daemon's startup (and SIGHUP) snapshot is never taken mid-write and is
// as fresh as any concurrent CLI commit (RA6X-006). The lock is released
// immediately; each signing cycle takes it again around its own load-save span.
func loadStateLocked(cfg *config.Config) (*statepkg.State, error) {
	lock, err := acquireStateLock(cfg.DataDir, 30*time.Second)
	if err != nil {
		return nil, fmt.Errorf("acquiring state lock: %w", err)
	}
	defer lock.release()
	state, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		return nil, fmt.Errorf("loading state: %w", err)
	}
	return state, nil
}

// checkOwnershipBootstrap initializes ownership transfer for a mutating CLI
// command and refuses to proceed when the tree does not exist and the command
// runs as root (RA6X-044).
func checkOwnershipBootstrap(dataDir string) error {
	status, err := fsutil.InitOwnershipTarget(dataDir)
	if err != nil {
		return err
	}
	if status == fsutil.OwnershipTargetMissing {
		return errors.New(fsutil.BootstrapInstructions(dataDir))
	}
	return nil
}

// persistState saves state and classifies the outcome (RA6X-049): a save whose
// file is visible but whose directory sync failed is reported as a warning and
// treated as success — the visible file IS the current generation and must not
// be rolled back — while a pre-rename failure is returned for the caller's
// rollback handling.
func persistState(state *statepkg.State) error {
	err := state.Save()
	if err == nil {
		return nil
	}
	if fsutil.IsCommitted(err) {
		slog.Warn("[CLI] state saved but its durability across power loss is uncertain", "error", err)
		return nil
	}
	return err
}

// commitConfigEdit classifies a config-file edit outcome the same way as
// persistState (RA6X-049).
func commitConfigEdit(err error) error {
	if err == nil {
		return nil
	}
	if fsutil.IsCommitted(err) {
		slog.Warn("[CLI] config file updated but its durability across power loss is uncertain", "error", err)
		return nil
	}
	return err
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	// The daemon creates its own tree as whatever account it runs as; an
	// inspection failure is still an error (RA6X-044).
	if _, err := fsutil.InitOwnershipTarget(cfg.DataDir); err != nil {
		return err
	}
	if err := signerpkg.EnsureDir(cfg.DataDir); err != nil {
		return fmt.Errorf("ensuring data_dir: %w", err)
	}

	// Refuse a duplicate daemon before touching any shared state (RA6X-006):
	// the instance lock is held for the life of the process.
	instance, err := acquireInstanceLock(cfg.DataDir)
	if err != nil {
		return err
	}
	defer instance.release()

	// Load the startup snapshot under the state lock, never before it.
	state, err := loadStateLocked(cfg)
	if err != nil {
		return err
	}

	// Override web config if --web flag provided
	webAddr, _ := cmd.Flags().GetString("web")
	if webAddr != "" {
		cfg.Web.Enabled = true
		cfg.Web.Listen = webAddr
	}

	// Re-apply the loopback guard the flag path bypassed: loadConfigAndState ran
	// Validate() before this override, so `--web :8053` (a form every shipped doc
	// used to recommend) would otherwise bind all interfaces with no auth. The
	// dashboard is unauthenticated; keep it loopback-only unless allow_remote is
	// explicitly set in config (R-005).
	if err := cfg.CheckWebFlagListen(); err != nil {
		return err
	}

	slog.Info("[DAEMON] Starting dnssec-tudor",
		"version", Version,
		"config", configPath,
		"poll_interval", cfg.PollInterval.String(),
		"zones", len(cfg.Zones))

	// Create daemon
	daemon := NewDaemon(cfg, state)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Start daemon
	errCh := make(chan error, 1)
	go func() {
		errCh <- daemon.Run()
	}()

	// Wait for signal or error
	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				// Reopen the log file first so logrotate (rename + SIGHUP) doesn't
				// leave us writing to the unlinked fd. Uses the same CLI-provided
				// level/format/output; only the underlying handle is refreshed (R-056).
				setupLogging()
				slog.Info("[DAEMON] Received SIGHUP, reloading configuration and state")
				newCfg, err := config.LoadConfig(configPath)
				if err != nil {
					slog.Error("[DAEMON] Failed to reload config", "error", err)
					continue
				}
				// Re-apply the --web flag override: LoadConfig rebuilt cfg from the
				// file only, so without this a SIGHUP would flip a flag-enabled
				// dashboard back to the file's (default-disabled) web config while
				// the web server keeps running — an inconsistent state (R-058).
				if webAddr != "" {
					newCfg.Web.Enabled = true
					newCfg.Web.Listen = webAddr
				}
				if err := newCfg.CheckWebFlagListen(); err != nil {
					slog.Error("[DAEMON] Reload rejected: --web override fails the loopback guard", "error", err)
					continue
				}
				newState, err := loadStateLocked(newCfg)
				if err != nil {
					slog.Error("[DAEMON] Failed to reload state", "error", err)
					continue
				}
				daemon.Reload(newCfg, newState)
			case syscall.SIGINT, syscall.SIGTERM:
				slog.Info("[DAEMON] Received shutdown signal", "signal", sig)
				// Run Shutdown in the background so we keep reading sigCh: a
				// second SIGINT/SIGTERM forces exit even if the graceful drain
				// is wedged on a hung hook or blackholed heartbeat (R-019).
				go daemon.Shutdown()
				for {
					select {
					case err := <-errCh:
						// Run() drained — an in-flight signing cycle finished
						// (and saved state) before the process exits.
						if err != nil {
							return fmt.Errorf("daemon error: %w", err)
						}
						return nil
					case sig2 := <-sigCh:
						if sig2 == syscall.SIGHUP {
							continue // ignore reloads once shutting down
						}
						slog.Warn("[DAEMON] Second shutdown signal; forcing exit", "signal", sig2)
						return fmt.Errorf("forced exit on repeated signal %v", sig2)
					}
				}
			}
		case err := <-errCh:
			if err != nil {
				return fmt.Errorf("daemon error: %w", err)
			}
			return nil
		}
	}
}

// runSign performs a one-shot sign of all zones
func runSign(cmd *cobra.Command, args []string) error {
	cfg, state, unlock, err := loadConfigStateLocked()
	if err != nil {
		return err
	}
	defer unlock()

	slog.Info("[CLI] Signing all zones", "count", len(cfg.Zones))

	signer := signerpkg.NewSigner(cfg, state)
	// Capture but don't early-return on a partial failure: healthy zones were
	// still signed (their signed files written), so the post-sign hook must
	// still fire and the status JSON must still print. We surface the failure
	// via the exit code at the end so cron/CI detect it (R-024).
	signedDomains, signErr := signer.SignAllReport()

	// Advance automatic ZSK rollovers on the one-shot path too, so a cron-only
	// deployment (no long-running `serve`) actually performs the rollover that
	// checkRolloverWarnings promises — otherwise the ZSK never rolls and the
	// warning eventually becomes "expired" (R-036). Mirrors the daemon's
	// per-zone post-sign rollover check; the advanced state is persisted below.
	rollover := newRolloverManager(cfg, state)
	for domain := range cfg.Zones {
		zoneState := state.GetZone(domain)
		if zoneState == nil || zoneState.ZSK == nil {
			continue
		}
		if err := rollover.CheckZSKRollover(domain); err != nil {
			slog.Error("[ROLLOVER] ZSK rollover check failed", "domain", domain, "error", err)
		}
		if err := rollover.CheckKSKRollover(domain); err != nil {
			slog.Error("[ROLLOVER] KSK rollover check failed", "domain", domain, "error", err)
		}
		if err := rollover.CheckAlgorithmRollover(domain); err != nil {
			slog.Error("[ROLLOVER] algorithm rollover check failed", "domain", domain, "error", err)
		}
	}
	if err := persistState(state); err != nil {
		return fmt.Errorf("saving state after rollover checks: %w", err)
	}

	// Post-sign hooks for the zones that actually signed, under the daemon's
	// contract (RA6X-043): one batch invocation with every signed domain when
	// coalescing, else one per-zone invocation each; none when nothing signed.
	// A hook failure means the signed files may not be served yet, so it is
	// surfaced through the exit code like a signing failure.
	var hookErr error
	if len(signedDomains) > 0 && hookConfigured(&cfg.Hooks) {
		slog.Info("[CLI] Executing post-sign hook", "signed", len(signedDomains))
		refs := make([]SignedZoneRef, 0, len(signedDomains))
		for _, domain := range signedDomains {
			signedAt := time.Time{}
			if zs := state.GetZone(domain); zs != nil {
				signedAt = zs.LastSigned
			}
			refs = append(refs, signedRef(cfg, domain, cfg.Zones[domain].Path, signedAt))
		}
		var confirmed []SignedZoneRef
		hookErr = firePostSignHooks(&cfg.Hooks, cfg.OutputDir, refs, nil, func(zones []SignedZoneRef, err error) {
			if err == nil {
				confirmed = append(confirmed, zones...)
			}
		})
		if hookErr != nil {
			slog.Error("[CLI] Post-sign hook failed", "error", hookErr)
		}
		if len(confirmed) > 0 {
			confirmPublicationCLI(state, confirmed)
		}
	}

	// Output status
	jsonData, err := statusJSON(state)
	if err != nil {
		return fmt.Errorf("generating status: %w", err)
	}
	fmt.Println(string(jsonData))

	if signErr != nil {
		return fmt.Errorf("signing failed: %w", signErr)
	}
	if hookErr != nil {
		return fmt.Errorf("zones signed, but the post-sign hook failed (signed output may not be served yet): %w", hookErr)
	}
	return nil
}

// runResign forces a re-sign of a specific domain
func runResign(cmd *cobra.Command, args []string) error {
	domain := args[0]

	cfg, state, unlock, err := loadConfigStateLocked()
	if err != nil {
		return err
	}
	defer unlock()

	// Check domain is managed
	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("domain %q is not managed (not in state.json)", domain)
	}

	// Check domain is in config
	zoneCfg, ok := cfg.Zones[domain]
	if !ok {
		return fmt.Errorf("domain %q is not in config file", domain)
	}

	slog.Info("[CLI] Force re-signing zone", "domain", domain)

	signer := signerpkg.NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// Save state
	if err := persistState(state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	_ = runPostSignHook(cfg, state, domain, zoneCfg.Path)

	fmt.Printf("Zone %s re-signed successfully.\n", domain)
	fmt.Printf("Signed zone written to: %s\n", filepath.Join(cfg.OutputDir, domain+".zone.signed"))

	return nil
}

// runStatus prints the current status
func runStatus(cmd *cobra.Command, args []string) error {
	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	doValidate, _ := cmd.Flags().GetBool("validate")

	domain, _ := cmd.Flags().GetString("domain")
	if domain != "" {
		// Show status for specific domain
		zoneState := state.GetZone(domain)
		if zoneState == nil {
			return fmt.Errorf("domain %q not found in state", domain)
		}
		output := &ZoneStatusOutput{
			Status:          zoneState.Status(),
			Serial:          zoneState.Serial,
			PublishedSerial: zoneState.PublishedSerial,
			LastSigned:      zoneState.LastSigned,
			SignaturesExp:   zoneState.SignaturesExp,
			KSK:             zoneState.KSK,
			ZSK:             zoneState.ZSK,
			Rollover:        zoneState.Rollover,
			Warnings:        zoneState.Warnings,
			Errors:          zoneState.Errors,
		}
		if doValidate {
			v := validate.NewValidator(cfg, state, cfg.Validation.Resolver, cfg.Validation.Timeout.Duration)
			output.Validation = v.ValidateZone(domain)
		}
		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling status: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Show status for all zones
	output := buildStatusOutput(state)
	if doValidate {
		v := validate.NewValidator(cfg, state, cfg.Validation.Resolver, cfg.Validation.Timeout.Duration)
		valOutput := v.ValidateAll()
		for domain, valResult := range valOutput.Zones {
			if zone, ok := output.Zones[domain]; ok {
				zone.Validation = valResult
			}
		}
	}
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("generating status: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

// runValidate checks DNSSEC visibility on the internet
func runValidate(cmd *cobra.Command, args []string) error {
	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	resolver, _ := cmd.Flags().GetString("resolver")
	if resolver == "" {
		resolver = cfg.Validation.Resolver
	}
	timeout := cfg.Validation.Timeout.Duration
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	v := validate.NewValidator(cfg, state, resolver, timeout)

	if len(args) == 1 {
		domain := args[0]
		result := v.ValidateZone(domain)
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling validation result: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	output := v.ValidateAll()
	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling validation output: %w", err)
	}
	fmt.Println(string(jsonData))
	return nil
}

// runAdd adds a new domain
func runAdd(cmd *cobra.Command, args []string) error {
	domain := args[0]
	// Record an absolute path: a cwd-relative arg works at add time but breaks
	// when the daemon later starts from a different working directory (systemd
	// with no WorkingDirectory → /). Resolve it now so the config always holds
	// an absolute path (R-017).
	zonePath, err := filepath.Abs(args[1])
	if err != nil {
		return fmt.Errorf("resolving zone path %q: %w", args[1], err)
	}

	if err := config.ValidateDomainName(domain); err != nil {
		return fmt.Errorf("invalid domain name: %w", err)
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

	// Validate zone file is parseable and has required records
	if err := signerpkg.ValidateZoneFile(domain, zonePath); err != nil {
		return fmt.Errorf("invalid zone file: %w", err)
	}

	// Check domain not already in config
	if _, ok := cfg.Zones[domain]; ok {
		return fmt.Errorf("domain %q is already in config file", domain)
	}

	// Check domain not already in state
	if state.GetZone(domain) != nil {
		return fmt.Errorf("domain %q is already managed (in state.json)", domain)
	}

	// R-029: reject a canonically-equivalent existing zone (differing only in case
	// or a trailing dot) so we never create a second competing key/DS set for one
	// DNS zone.
	if existing, dup := canonicalConflict(cfg, state, domain); dup {
		return fmt.Errorf("domain %q is the same DNS zone as already-managed %q (case/trailing-dot only); use the existing entry", domain, existing)
	}

	slog.Info("[CLI] Adding domain", "domain", domain, "path", zonePath)

	// Pre-flight: confirm the config file is appendable BEFORE doing anything
	// destructive. The `add` command must update three things on disk — keys,
	// signed zone, state.json — plus a final append to the config file. If
	// the config append is going to fail (the common case is a non-writable
	// config: root-owned, daemon user runs `add`), surface that here so we
	// don't leave half-added zones on disk.
	if err := preflightConfigAppend(configPath); err != nil {
		return fmt.Errorf("config file not writable for zone append: %w", err)
	}

	// Add to in-memory config so signing works
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}

	// Key files may already exist on disk from a previous management period
	// (zone removed and re-added). Reusing them preserves the DS chain of
	// trust — generating fresh keys while the registrar's DS still points
	// at the old KSK would SERVFAIL the zone the moment the new signed
	// output goes live. RecoverOrGenerateKeys only generates when no key
	// files are present. Capture which slots were empty — BOTH halves absent,
	// since a half-present pair is refused, not regenerated — so a rollback
	// only deletes keys this command created.
	keysDir := cfg.KeysDir()
	kskGenerated := keyPairAbsent(keysDir, domain, "ksk")
	zskGenerated := keyPairAbsent(keysDir, domain, "zsk")

	// R-011: snapshot any pre-existing signed output BEFORE the sign step may
	// overwrite it, so a failed add — especially a re-add that reuses keys from a
	// previous management period — restores the last known-good signed zone a
	// nameserver may still be serving, instead of deleting it.
	signedPath := filepath.Join(cfg.OutputDir, domain+".zone.signed")
	var origOutput []byte
	outputExisted := false
	if b, rerr := os.ReadFile(signedPath); rerr == nil {
		origOutput = b
		outputExisted = true
	} else if !os.IsNotExist(rerr) {
		return fmt.Errorf("reading existing signed output %s: %w", signedPath, rerr)
	}

	// From here on, any failure must roll back side effects — partial keys,
	// signed zone, state entry — so a retry of `add` starts from a clean slate.
	keyGen := signerpkg.NewKeyGenerator(cfg)
	ksk, zsk, err := signerpkg.RecoverOrGenerateKeys(keyGen, domain)
	if err != nil {
		unwindAdd(cfg, state, domain, kskGenerated, zskGenerated, origOutput, outputExisted)
		return fmt.Errorf("preparing keys: %w", err)
	}

	// Create zone state
	zoneState := &statepkg.ZoneState{
		Path: zonePath,
		KSK:  ksk,
		ZSK:  zsk,
	}
	state.ClearRemoved(domain)
	state.SetZone(domain, zoneState)

	// Sign the zone
	signer := signerpkg.NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		unwindAdd(cfg, state, domain, kskGenerated, zskGenerated, origOutput, outputExisted)
		return fmt.Errorf("signing zone: %w", err)
	}

	if err := persistState(state); err != nil {
		unwindAdd(cfg, state, domain, kskGenerated, zskGenerated, origOutput, outputExisted)
		return fmt.Errorf("saving state: %w", err)
	}

	// Config append happens last. The pre-flight makes failure here unlikely,
	// but if it still fails (race, disk full), unwind everything so state.json
	// stays consistent with the config file.
	if err := commitConfigEdit(config.AddZoneToConfigFile(configPath, domain, zonePath)); err != nil {
		unwindAdd(cfg, state, domain, kskGenerated, zskGenerated, origOutput, outputExisted)
		return fmt.Errorf("adding zone to config file: %w", err)
	}
	slog.Info("[CLI] Added zone to config file", "config", configPath)

	// Print DS records — load actual key for proper DS computation. The add has
	// already fully committed (keys written, zone signed, state + config
	// persisted), so a failure to load the KSK for the convenience DS printout
	// must NOT fail the command: warn and point the operator at `ds` (R-060).
	kskKey, err := keyGen.LoadPublicKey(domain, "ksk")

	fmt.Printf("\nDomain %s added successfully.\n", domain)
	fmt.Printf("  Config updated: %s\n", configPath)
	fmt.Printf("  Signed zone:    %s\n\n", filepath.Join(cfg.OutputDir, domain+".zone.signed"))
	if err != nil {
		slog.Warn("[CLI] zone added, but the KSK could not be loaded to print its DS record",
			"domain", domain, "error", err)
		fmt.Printf("Could not print the DS record automatically; run `dnssec-tudor ds %s` to retrieve it.\n", domain)
	} else {
		if kskGenerated {
			fmt.Println("Add the following DS record to your registrar:")
		} else {
			fmt.Println("Existing keys were reused. Verify this DS record matches your registrar:")
		}
		fmt.Println(signerpkg.FormatDSRecordsFromKey(domain, kskKey))
	}
	fmt.Println("Note: a running daemon picks up the new zone after SIGHUP (config reload).")

	hookOK := runPostSignHook(cfg, state, domain, zonePath)

	// If a registrar is configured for this zone and auto-publish is on,
	// push the DS record automatically. Failures are non-fatal. A DS is only
	// published for a zone that is confirmed served (RA6X-004): publishing it
	// while the hook failed would point the parent at a zone nobody answers for.
	if hookOK {
		MaybeAutoPublishDS(cfg, state, domain, "add")
	} else {
		fmt.Printf("DS auto-publish skipped: the post-sign hook failed. Once the zone is served, run `dnssec-tudor registrar push %s`.\n", domain)
	}

	return nil
}

// runRemove removes a domain from management
func runRemove(cmd *cobra.Command, args []string) error {
	domain := args[0]

	cfg, state, unlock, err := loadConfigStateLocked()
	if err != nil {
		return err
	}
	defer unlock()

	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("domain %q is not managed", domain)
	}
	slog.Info("[CLI] Removing domain from management", "domain", domain)

	// Transactional removal (R-008): preflight the config file is writable, remove the
	// zone from the config FIRST (so a running daemon can't re-adopt it next cycle), then
	// clear state. On a state-save failure, restore the config entry so the two stay
	// consistent. Keys are never deleted — a DS at the registrar may still reference them.
	inConfig := false
	// R-010: snapshot the EXACT original config bytes so a later state-save failure
	// can restore the file verbatim. The prior rollback re-added the zone via
	// AddZoneToConfigFile, which reconstructs only domain+path and silently loses the
	// zone's algorithm/lifetimes/serial policy/registrar settings/comments/ordering.
	var origConfig []byte
	if _, ok := cfg.Zones[domain]; ok {
		inConfig = true
		var readErr error
		origConfig, readErr = os.ReadFile(configPath)
		if readErr != nil {
			return fmt.Errorf("reading config before removal: %w", readErr)
		}
		if err := preflightConfigAppend(configPath); err != nil {
			return fmt.Errorf("config file %s not writable (needed to remove the zone entry): %w", configPath, err)
		}
		if err := commitConfigEdit(config.RemoveZoneFromConfigFile(configPath, domain)); err != nil {
			if err == config.ErrZoneNotInConfig {
				// The parsed config confirmed the zone IS present, yet the
				// rewriter could not locate its table header (a hand-edited
				// form the line matcher doesn't recognize). Printing success
				// would leave the entry in the file and a SIGHUPed daemon
				// would re-adopt the zone — surface it instead.
				return fmt.Errorf("zone %q is in the config but its [zones.%q] table header could not be located in %s; remove the entry by hand, then re-run `dnssec-tudor remove %s`",
					domain, domain, configPath, domain)
			}
			return fmt.Errorf("removing zone from config file: %w", err)
		}
	}

	// Record a deletion marker rather than merely dropping the entry, so a
	// running daemon whose configuration still lists the zone cannot re-create
	// it from that stale configuration before the documented SIGHUP (RA6X-025).
	state.MarkRemoved(domain)
	if err := persistState(state); err != nil {
		if inConfig {
			// Restore the exact original config bytes (all keys/comments/order),
			// preserving ownership/mode, so the failed removal leaves config and
			// state consistent and complete (R-010).
			if aerr := fsutil.WriteConfigFileAtomic(configPath, origConfig); aerr != nil {
				slog.Error("[CLI] Rollback: failed to restore original config after state-save failure",
					"domain", domain, "error", aerr)
			}
		}
		return fmt.Errorf("saving state: %w", err)
	}

	fmt.Printf("Domain %s removed from management.\n", domain)
	fmt.Printf("Note: Key files were NOT deleted (a DS at your registrar may still reference them).\n")
	fmt.Printf("Note: A running daemon still holds the old config in memory; send it SIGHUP to reload.\n")
	return nil
}

// runRolloverStart begins a KSK rollover
func runRolloverStart(cmd *cobra.Command, args []string) error {
	domain := args[0]

	cfg, state, unlock, err := loadConfigStateLocked()
	if err != nil {
		return err
	}
	defer unlock()

	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("domain %q is not managed", domain)
	}

	if zoneState.Rollover != nil {
		return fmt.Errorf("rollover already in progress for %s (state: %s)", domain, zoneState.Rollover.State)
	}

	slog.Info("[CLI] Starting KSK rollover", "domain", domain)

	rollover := signerpkg.NewRolloverManager(cfg, state)
	if err := rollover.StartKSKRollover(domain); err != nil {
		return fmt.Errorf("starting rollover: %w", err)
	}

	// Sign with both keys
	signer := signerpkg.NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		return fmt.Errorf("signing zone: %w", err)
	}

	if err := persistState(state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	hookOK := runPostSignHook(cfg, state, domain, zoneState.Path)

	// Print new DS
	fmt.Printf("KSK rollover started for %s.\n\n", domain)
	fmt.Println("Both keys are now in the zone. Add the NEW DS record at your registrar:")
	keyGen := signerpkg.NewKeyGenerator(cfg)
	kskKey, err := keyGen.LoadPublicKey(domain, "ksk")
	if err != nil {
		return fmt.Errorf("loading new KSK for DS: %w", err)
	}
	fmt.Println(signerpkg.FormatDSRecordsFromKey(domain, kskKey))
	fmt.Printf("\nOnce the new DS is published, run: dnssec-tudor rollover complete %s\n", domain)

	if hookOK {
		MaybeAutoPublishDS(cfg, state, domain, "rollover_start")
	} else {
		fmt.Printf("DS auto-publish skipped: the post-sign hook failed, so the new KSK is not confirmed served yet. Once it is, run `dnssec-tudor registrar push %s`.\n", domain)
	}

	return nil
}

// runRolloverStatus shows rollover status
func runRolloverStatus(cmd *cobra.Command, args []string) error {
	domain := args[0]

	_, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("domain %q is not managed", domain)
	}

	if zoneState.Rollover == nil {
		fmt.Printf("No rollover in progress for %s\n", domain)
		return nil
	}

	output, err := json.MarshalIndent(zoneState.Rollover, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling rollover status: %w", err)
	}
	fmt.Println(string(output))
	return nil
}

func runRolloverComplete(cmd *cobra.Command, args []string) error {
	domain := args[0]

	cfg, state, unlock, err := loadConfigStateLocked()
	if err != nil {
		return err
	}
	defer unlock()

	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("domain %q is not managed", domain)
	}

	if zoneState.Rollover == nil {
		return fmt.Errorf("no rollover in progress for %s", domain)
	}
	rollover := zoneState.Rollover
	if rollover.Type != "ksk" && rollover.Type != "algorithm" {
		return fmt.Errorf("cannot complete rollover type %q manually", rollover.Type)
	}
	if !rollover.NeedsOperator() || rollover.State == statepkg.AlgoRolloverStateOldDSRemoval {
		return fmt.Errorf("rollover for %s is in phase %s: retirement continues automatically (the daemon or `dnssec-tudor sign` advances it); current action: %s", domain, rollover.State, rollover.Action)
	}

	// Before the old KSK can ever be retired, the new KSK's DS must be live at
	// EVERY parent server and the parent's DS TTL must elapse (RA6X-003): a
	// resolver that fetched the old-only DS set just before the new DS appeared
	// holds it that long, and would go bogus if the old KSK vanished from the
	// DNSKEY RRset earlier. Completion therefore records the observation and
	// starts the propagation wait; the daemon retires the old key afterwards.
	// --force is the explicit escape hatch for operators who verified
	// propagation another way (R-037): the wait then starts now with the
	// configured parent_ds_ttl.
	force, _ := cmd.Flags().GetBool("force")
	now := time.Now().UTC()
	var parentDSTTL uint32
	if force {
		fmt.Println("Warning: --force set; skipping the parent-DS check. The old key is retired after the configured parent_ds_ttl from now.")
	} else {
		keyGen := signerpkg.NewKeyGenerator(cfg)
		newKSK, err := keyGen.LoadPublicKey(domain, "ksk")
		if err != nil {
			return fmt.Errorf("loading the new KSK to verify its DS: %w", err)
		}
		v := validate.NewValidator(cfg, state, cfg.Validation.Resolver, cfg.Validation.Timeout.Duration)
		obs, err := v.ProbeParentDS(domain, []*dns.DNSKEY{newKSK})
		if err != nil {
			return fmt.Errorf("refusing to complete: could not query every parent server for the new DS (%v); retry, or pass --force if you have verified it another way", err)
		}
		if !obs.PresentOnAll[newKSK.KeyTag()] {
			return fmt.Errorf("refusing to complete: the new KSK's DS (tag %d) is not visible at every parent server yet (%d server(s) checked).\n"+
				"Publish the new DS at your registrar and wait for it to propagate, then retry — or pass --force if you have verified it another way", newKSK.KeyTag(), len(obs.Servers))
		}
		parentDSTTL = obs.TTL
		fmt.Printf("Verified the new KSK's DS is present at all %d parent server(s) (DS TTL %ds).\n", len(obs.Servers), obs.TTL)
	}
	if parentDSTTL == 0 {
		parentDSTTL = uint32(cfg.ParentDSTTLFallback() / time.Second)
	}

	rolloverMgr := newRolloverManager(cfg, state)
	switch rollover.Type {
	case "ksk":
		slog.Info("[CLI] Completing KSK rollover", "domain", domain)
		if err := rolloverMgr.CompleteKSKRollover(domain, now, parentDSTTL); err != nil {
			return fmt.Errorf("completing KSK rollover: %w", err)
		}
		fmt.Printf("KSK rollover for %s is entering its retirement wait.\n", domain)
		fmt.Printf("Both KSKs stay published until %s (parent DS TTL); the old KSK is then retired automatically by the daemon or the next `dnssec-tudor sign`.\n",
			now.Add(time.Duration(parentDSTTL)*time.Second).Format(time.RFC3339))
		fmt.Println("You may remove the OLD DS record from your registrar now.")
	case "algorithm":
		slog.Info("[CLI] Completing algorithm rollover", "domain", domain)
		if err := rolloverMgr.CompleteAlgorithmRollover(domain, now, parentDSTTL); err != nil {
			return fmt.Errorf("completing algorithm rollover: %w", err)
		}
		fmt.Printf("Algorithm rollover for %s is entering its retirement sequence.\n", domain)
		fmt.Printf("Both algorithms stay published until %s (parent DS TTL). Then remove the OLD DS record (old algorithm) at your registrar; the old-algorithm keys are retired one DS TTL after it is gone from every parent server.\n",
			now.Add(time.Duration(parentDSTTL)*time.Second).Format(time.RFC3339))
	}

	// The key set does not change yet; re-sign so state and output stay coherent.
	signer := signerpkg.NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		return fmt.Errorf("signing zone: %w", err)
	}

	if err := persistState(state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	hookOK := runPostSignHook(cfg, state, domain, zoneState.Path)

	// Removing the old DS at the parent is safe from here: every resolver
	// validates through a DS that matches a served KSK. Only the old KEY's
	// retirement waits (above).
	if hookOK {
		MaybeAutoPublishDS(cfg, state, domain, "rollover_complete")
	} else {
		fmt.Printf("DS auto-publish skipped: the post-sign hook failed. Run `dnssec-tudor registrar push %s` once the zone is served.\n", domain)
	}

	return nil
}

// runRolloverAlgorithm starts an algorithm rollover
func runRolloverAlgorithm(cmd *cobra.Command, args []string) error {
	domain := args[0]
	targetAlgorithm := args[1]

	// Validate algorithm
	validAlgorithms := map[string]bool{
		"ED25519":         true,
		"ECDSAP256SHA256": true,
		"ECDSAP384SHA384": true,
	}
	if !validAlgorithms[targetAlgorithm] {
		return fmt.Errorf("invalid algorithm %q (valid: ED25519, ECDSAP256SHA256, ECDSAP384SHA384)", targetAlgorithm)
	}

	cfg, state, unlock, err := loadConfigStateLocked()
	if err != nil {
		return err
	}
	defer unlock()

	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("domain %q is not managed", domain)
	}

	rolloverMgr := signerpkg.NewRolloverManager(cfg, state)
	if err := rolloverMgr.StartAlgorithmRollover(domain, targetAlgorithm); err != nil {
		return fmt.Errorf("starting algorithm rollover: %w", err)
	}

	// Re-sign with both algorithms
	signer := signerpkg.NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		return fmt.Errorf("signing zone: %w", err)
	}

	if err := persistState(state); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	hookOK := runPostSignHook(cfg, state, domain, zoneState.Path)

	// Get new DS record
	keyGen := signerpkg.NewKeyGenerator(cfg)
	ksk, err := keyGen.LoadPublicKey(domain, "ksk")
	if err != nil {
		return fmt.Errorf("loading new KSK: %w", err)
	}

	ds := signerpkg.ComputeDS(domain, ksk, 2) // SHA-256 digest

	fmt.Printf("Algorithm rollover started for %s.\n", domain)
	fmt.Printf("Old algorithm: %s\n", state.GetZone(domain).Rollover.OldAlgorithm)
	fmt.Printf("New algorithm: %s\n\n", targetAlgorithm)
	fmt.Println("Add the following DS record to your registrar:")
	fmt.Println()
	fmt.Println(ds.String())
	fmt.Println()
	fmt.Printf("After the new DS propagates, run: dnssec-tudor rollover complete %s\n", domain)

	if hookOK {
		MaybeAutoPublishDS(cfg, state, domain, "rollover_start")
	} else {
		fmt.Printf("DS auto-publish skipped: the post-sign hook failed, so the new KSK is not confirmed served yet. Once it is, run `dnssec-tudor registrar push %s`.\n", domain)
	}

	return nil
}

// runDS prints DS records for a domain
func runDS(cmd *cobra.Command, args []string) error {
	domain := args[0]
	jsonOutput, _ := cmd.Flags().GetBool("json")

	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("domain %q is not managed", domain)
	}

	if zoneState.KSK == nil {
		return fmt.Errorf("no KSK found for %s", domain)
	}

	// Load the actual key to compute DS (public half is sufficient)
	keyGen := signerpkg.NewKeyGenerator(cfg)
	ksk, err := keyGen.LoadPublicKey(domain, "ksk")
	if err != nil {
		return fmt.Errorf("loading KSK: %w", err)
	}

	if jsonOutput {
		ds := signerpkg.ComputeDS(domain, ksk, dns.SHA256)
		out := struct {
			Domain     string `json:"domain"`
			KeyTag     uint16 `json:"key_tag"`
			Algorithm  uint8  `json:"algorithm"`
			DigestType uint8  `json:"digest_type"`
			Digest     string `json:"digest"`
			Record     string `json:"record"`
		}{
			Domain:     domain,
			KeyTag:     ds.KeyTag,
			Algorithm:  ds.Algorithm,
			DigestType: ds.DigestType,
			Digest:     ds.Digest,
			Record:     ds.String(),
		}
		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling DS: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	dsOutput := signerpkg.FormatDSRecordsFromKey(domain, ksk)
	fmt.Println(dsOutput)
	return nil
}

// runDNSKEY prints DNSKEY records for a domain
func runDNSKEY(cmd *cobra.Command, args []string) error {
	domain := args[0]
	jsonOutput, _ := cmd.Flags().GetBool("json")

	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("domain %q is not managed", domain)
	}

	// Load the actual keys (public halves only)
	keyGen := signerpkg.NewKeyGenerator(cfg)
	var ksk, zsk *dns.DNSKEY

	if zoneState.KSK != nil {
		ksk, err = keyGen.LoadPublicKey(domain, "ksk")
		if err != nil {
			slog.Warn("[CLI] Failed to load KSK", "error", err)
		}
	}

	if zoneState.ZSK != nil {
		zsk, err = keyGen.LoadPublicKey(domain, "zsk")
		if err != nil {
			slog.Warn("[CLI] Failed to load ZSK", "error", err)
		}
	}

	if jsonOutput {
		type keyJSON struct {
			Flags     uint16 `json:"flags"`
			Protocol  uint8  `json:"protocol"`
			Algorithm uint8  `json:"algorithm"`
			PublicKey string `json:"public_key"`
			KeyTag    uint16 `json:"key_tag"`
			Record    string `json:"record"`
		}
		out := struct {
			Domain string   `json:"domain"`
			KSK    *keyJSON `json:"ksk,omitempty"`
			ZSK    *keyJSON `json:"zsk,omitempty"`
		}{Domain: domain}

		if ksk != nil {
			out.KSK = &keyJSON{
				Flags: ksk.Flags, Protocol: ksk.Protocol,
				Algorithm: ksk.Algorithm, PublicKey: ksk.PublicKey,
				KeyTag: ksk.KeyTag(), Record: ksk.String(),
			}
		}
		if zsk != nil {
			out.ZSK = &keyJSON{
				Flags: zsk.Flags, Protocol: zsk.Protocol,
				Algorithm: zsk.Algorithm, PublicKey: zsk.PublicKey,
				KeyTag: zsk.KeyTag(), Record: zsk.String(),
			}
		}

		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling DNSKEY: %w", err)
		}
		fmt.Println(string(data))
		return nil
	}

	dnskeyOutput := signerpkg.FormatDNSKEYRecordsFromKeys(domain, ksk, zsk)
	fmt.Println(dnskeyOutput)
	return nil
}

// runImport imports existing BIND-style keys
func runImport(cmd *cobra.Command, args []string) error {
	domain := args[0]
	// Store an absolute path (see runAdd / R-017): a relative path recorded here
	// breaks once the daemon starts from a different working directory.
	zonePath, err := filepath.Abs(args[1])
	if err != nil {
		return fmt.Errorf("resolving zone path %q: %w", args[1], err)
	}
	kskPath, _ := cmd.Flags().GetString("ksk")
	zskPath, _ := cmd.Flags().GetString("zsk")

	if err := config.ValidateDomainName(domain); err != nil {
		return fmt.Errorf("invalid domain name: %w", err)
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

	slog.Info("[CLI] Importing keys for domain", "domain", domain, "ksk", kskPath, "zsk", zskPath)

	// Read both pairs. Nothing below this point writes anything until every
	// check on the imported material has passed (RA6X-024).
	ksk, kskPriv, err := loadBindKeyPair(kskPath)
	if err != nil {
		return fmt.Errorf("loading KSK from %s: %w", kskPath, err)
	}
	zsk, zskPriv, err := loadBindKeyPair(zskPath)
	if err != nil {
		return fmt.Errorf("loading ZSK from %s: %w", zskPath, err)
	}
	if ksk.Flags != 257 {
		return fmt.Errorf("KSK has wrong flags %d (expected 257 for KSK)", ksk.Flags)
	}
	if zsk.Flags != 256 {
		return fmt.Errorf("ZSK has wrong flags %d (expected 256 for ZSK)", zsk.Flags)
	}

	// R-009: reject a mismatched-algorithm KSK/ZSK import BEFORE touching any live
	// file. This signer signs the DNSKEY RRset with the KSK algorithm and ordinary
	// RRsets with the ZSK algorithm only; if the two keys use different algorithms
	// the published DNSKEY RRset signals both while no RRset is signed with every
	// algorithm — an algorithm-incomplete zone that standards-conforming validators
	// (RFC 6840 §5.11) may reject. Same-algorithm separate KSK/ZSK keys are fine; a
	// genuine algorithm change must go through the dedicated algorithm-rollover flow.
	if ksk.Algorithm != zsk.Algorithm {
		return fmt.Errorf("refusing to import a KSK (%s) and ZSK (%s) with different algorithms: the result would be an algorithm-incomplete zone (RFC 6840 §5.11); import same-algorithm keys or use `rollover algorithm`",
			signerpkg.AlgorithmName(ksk.Algorithm), signerpkg.AlgorithmName(zsk.Algorithm))
	}

	// Canonical owner, protocol, supported algorithm, role flags, correspondence
	// and real signing capability — all before any live artifact changes.
	if err := signerpkg.ValidateKeyForImport(domain, "ksk", ksk, kskPriv); err != nil {
		return fmt.Errorf("refusing to import: %w", err)
	}
	if err := signerpkg.ValidateKeyForImport(domain, "zsk", zsk, zskPriv); err != nil {
		return fmt.Errorf("refusing to import: %w", err)
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
			Created:     now, // We don't know the original creation time
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

	fmt.Printf("\nDomain %s imported successfully.\n", domain)
	fmt.Printf("  KSK: %d (%s)\n", ksk.KeyTag(), signerpkg.AlgorithmName(ksk.Algorithm))
	fmt.Printf("  ZSK: %d (%s)\n", zsk.KeyTag(), signerpkg.AlgorithmName(zsk.Algorithm))
	fmt.Printf("  Config updated: %s\n", configPath)
	fmt.Printf("  Signed zone:    %s\n\n", signer.OutputPath(domain))
	fmt.Println("DS record (verify this matches what's at your registrar):")
	dsOutput := signerpkg.FormatDSRecordsFromKey(domain, ksk)
	fmt.Println(dsOutput)
	fmt.Println("Note: a running daemon picks up the new zone after SIGHUP (config reload).")

	_ = runPostSignHook(cfg, state, domain, zonePath)

	return nil
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
			note("could not remove the zone from state.json (%v); run `dnssec-tudor remove %s` before retrying", err, tx.domain)
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

// loadBindKeyPair loads a BIND-style key pair from the given base path
func loadBindKeyPair(basePath string) (*dns.DNSKEY, []byte, error) {
	// Read public key
	keyFile := basePath + ".key"
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", keyFile, err)
	}

	// Parse DNSKEY from file
	dnskey, err := signerpkg.ParseDNSKEYFromFile(string(keyData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", keyFile, err)
	}

	// Read private key
	privFile := basePath + ".private"
	privData, err := os.ReadFile(privFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", privFile, err)
	}

	privateKey, err := signerpkg.ParsePrivateKeyFromFile(string(privData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", privFile, err)
	}

	// Validate the imported pair before it is ever written or signed with (R-010): a
	// 32-byte-seed ED25519 key is accepted here, and a mismatched .key/.private pair is
	// rejected up front rather than panicking or emitting a bogus zone at sign time.
	if err := signerpkg.VerifyKeyPairCorrespondence(dnskey, privateKey); err != nil {
		return nil, nil, fmt.Errorf("validating key pair at %s: %w", basePath, err)
	}

	return dnskey, privateKey, nil
}
