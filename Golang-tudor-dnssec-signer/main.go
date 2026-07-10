package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/miekg/dns"
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
)

func main() {
	// Root command
	rootCmd := &cobra.Command{
		Use:   "dnssec-tudor",
		Short: "A minimal DNSSEC signing daemon",
		Long: `dnssec-tudor is a minimal, opinionated DNSSEC signing daemon for sysadmins
who just want zones signed without the complexity of full-featured solutions.

It watches unsigned zone files, generates keys, signs zones automatically,
and outputs signed zones for authoritative nameservers like NSD.`,
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
		RunE:  runRegistrarGet,
	}
	registrarPushCmd := &cobra.Command{
		Use:   "push <domain>",
		Short: "Push expected DS records to the registrar (idempotent)",
		Args:  cobra.ExactArgs(1),
		RunE:  runRegistrarPush,
	}
	registrarVerifyCmd := &cobra.Command{
		Use:   "verify <domain>",
		Short: "Compare expected vs published DS records (exit 1 on drift)",
		Args:  cobra.ExactArgs(1),
		RunE:  runRegistrarVerify,
	}
	registrarClearCmd := &cobra.Command{
		Use:   "clear <domain>",
		Short: "Remove all DS records at the registrar",
		Args:  cobra.ExactArgs(1),
		RunE:  runRegistrarClear,
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
			var err error
			handler, err = newSyslogHandler(level)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to connect to syslog: %v, falling back to stderr\n", err)
				handler = slog.NewTextHandler(os.Stderr, opts)
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

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func loadConfigAndState() (*Config, *State, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("loading config: %w", err)
	}

	// Capture the data_dir owner before any writes so CLI commands run as
	// root will chown what they create. No-op for non-root invocations.
	InitOwnershipTarget(cfg.DataDir)

	state, err := LoadState(cfg.StatePath())
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
func loadConfigStateLocked() (cfg *Config, state *State, unlock func(), err error) {
	cfg, err = LoadConfig(configPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading config: %w", err)
	}
	InitOwnershipTarget(cfg.DataDir)
	if err := ensureDir(cfg.DataDir); err != nil {
		return nil, nil, nil, fmt.Errorf("ensuring data_dir for state lock: %w", err)
	}
	lock, err := acquireStateLock(cfg.DataDir, 30*time.Second)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("acquiring state lock: %w", err)
	}
	state, err = LoadState(cfg.StatePath())
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

// runPostSignHook fires the configured post-sign hook synchronously after a
// CLI command re-signed a zone. CLI commands must run the hook synchronously
// — the async daemon variant would be killed when the process exits — and
// they must run it at all: without this, `rollover complete` would write a
// new signed zone that NSD doesn't load until the next natural re-sign.
// Hook failures are logged, never fatal — the signing itself succeeded.
func runPostSignHook(cfg *Config, domain, zonePath string) {
	if cfg.Hooks.PostSign == "" && len(cfg.Hooks.PostSignCmd) == 0 {
		return
	}
	slog.Info("[CLI] Executing post-sign hook", "domain", domain)
	hookEnv := &HookEnv{
		Domain:     domain,
		ZonePath:   zonePath,
		SignedPath: filepath.Join(cfg.OutputDir, domain+".zone.signed"),
		OutputDir:  cfg.OutputDir,
	}
	if err := executeHookSync(&cfg.Hooks, hookEnv); err != nil {
		slog.Error("[CLI] Post-sign hook failed", "domain", domain, "error", err)
	}
}

// unwindAdd undoes the on-disk side effects of a partial `add`: removes the
// zone from in-memory state, persists state.json, and deletes the signed
// zone file. Key files are deleted only when this `add` generated them —
// keys recovered from a previous management period must survive the
// rollback, since a DS at the registrar may still reference them.
// Best-effort — failures are logged but not returned, so the original error
// from `add` surfaces unchanged.
func unwindAdd(cfg *Config, state *State, domain string, removeKSK, removeZSK bool) {
	state.RemoveZone(domain)
	if err := state.Save(); err != nil {
		slog.Warn("[CLI] Rollback: failed to save state", "domain", domain, "error", err)
	}

	signedPath := filepath.Join(cfg.OutputDir, domain+".zone.signed")
	if err := os.Remove(signedPath); err != nil && !os.IsNotExist(err) {
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
func runServe(cmd *cobra.Command, args []string) error {
	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	// Override web config if --web flag provided
	webAddr, _ := cmd.Flags().GetString("web")
	if webAddr != "" {
		cfg.Web.Enabled = true
		cfg.Web.Listen = webAddr
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
				slog.Info("[DAEMON] Received SIGHUP, reloading configuration and state")
				newCfg, err := LoadConfig(configPath)
				if err != nil {
					slog.Error("[DAEMON] Failed to reload config", "error", err)
					continue
				}
				newState, err := LoadState(newCfg.StatePath())
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

	signer := NewSigner(cfg, state)
	if err := signer.SignAll(); err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// Execute post-sign hook once after all zones are signed
	if cfg.Hooks.PostSign != "" || len(cfg.Hooks.PostSignCmd) > 0 {
		slog.Info("[CLI] Executing post-sign hook")
		if err := executeHookSync(&cfg.Hooks, &HookEnv{OutputDir: cfg.OutputDir}); err != nil {
			slog.Error("[CLI] Post-sign hook failed", "error", err)
		}
	}

	// Output status
	jsonData, err := state.ToJSON()
	if err != nil {
		return fmt.Errorf("generating status: %w", err)
	}
	fmt.Println(string(jsonData))

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

	signer := NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}

	// Save state
	if err := state.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	runPostSignHook(cfg, domain, zoneCfg.Path)

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
			v := NewValidator(cfg, state, cfg.Validation.Resolver, cfg.Validation.Timeout.Duration)
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
	output := state.ToStatusOutput()
	if doValidate {
		v := NewValidator(cfg, state, cfg.Validation.Resolver, cfg.Validation.Timeout.Duration)
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

	v := NewValidator(cfg, state, resolver, timeout)

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
	zonePath := args[1]

	if err := ValidateDomainName(domain); err != nil {
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
	if err := ValidateZoneFile(domain, zonePath); err != nil {
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
	cfg.Zones[domain] = ZoneConfig{Path: zonePath}

	// Key files may already exist on disk from a previous management period
	// (zone removed and re-added). Reusing them preserves the DS chain of
	// trust — generating fresh keys while the registrar's DS still points
	// at the old KSK would SERVFAIL the zone the moment the new signed
	// output goes live. recoverOrGenerateKeys only generates when no key
	// files are present. Capture which slots were empty so a rollback only
	// deletes keys this command created.
	keysDir := cfg.KeysDir()
	kskGenerated := !fileExists(filepath.Join(keysDir, domain+".ksk.key"))
	zskGenerated := !fileExists(filepath.Join(keysDir, domain+".zsk.key"))

	// From here on, any failure must roll back side effects — partial keys,
	// signed zone, state entry — so a retry of `add` starts from a clean slate.
	keyGen := NewKeyGenerator(cfg)
	ksk, zsk, err := recoverOrGenerateKeys(keyGen, domain)
	if err != nil {
		unwindAdd(cfg, state, domain, kskGenerated, zskGenerated)
		return fmt.Errorf("preparing keys: %w", err)
	}

	// Create zone state
	zoneState := &ZoneState{
		Path: zonePath,
		KSK:  ksk,
		ZSK:  zsk,
	}
	state.SetZone(domain, zoneState)

	// Sign the zone
	signer := NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		unwindAdd(cfg, state, domain, kskGenerated, zskGenerated)
		return fmt.Errorf("signing zone: %w", err)
	}

	if err := state.Save(); err != nil {
		unwindAdd(cfg, state, domain, kskGenerated, zskGenerated)
		return fmt.Errorf("saving state: %w", err)
	}

	// Config append happens last. The pre-flight makes failure here unlikely,
	// but if it still fails (race, disk full), unwind everything so state.json
	// stays consistent with the config file.
	if err := AddZoneToConfigFile(configPath, domain, zonePath); err != nil {
		unwindAdd(cfg, state, domain, kskGenerated, zskGenerated)
		return fmt.Errorf("adding zone to config file: %w", err)
	}
	slog.Info("[CLI] Added zone to config file", "config", configPath)

	// Print DS records - load actual key for proper DS computation
	kskKey, err := keyGen.LoadPublicKey(domain, "ksk")
	if err != nil {
		return fmt.Errorf("loading KSK for DS: %w", err)
	}

	fmt.Printf("\nDomain %s added successfully.\n", domain)
	fmt.Printf("  Config updated: %s\n", configPath)
	fmt.Printf("  Signed zone:    %s\n\n", filepath.Join(cfg.OutputDir, domain+".zone.signed"))
	if kskGenerated {
		fmt.Println("Add the following DS record to your registrar:")
	} else {
		fmt.Println("Existing keys were reused. Verify this DS record matches your registrar:")
	}
	dsOutput := FormatDSRecordsFromKey(domain, kskKey)
	fmt.Println(dsOutput)
	fmt.Println("Note: a running daemon picks up the new zone after SIGHUP (config reload).")

	runPostSignHook(cfg, domain, zonePath)

	// If a registrar is configured for this zone and auto-publish is on,
	// push the DS record automatically. Failures are non-fatal.
	maybeAutoPublishDS(cfg, state, domain, "add")

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
	zonePath := zoneState.Path

	slog.Info("[CLI] Removing domain from management", "domain", domain)

	// Transactional removal (R-008): preflight the config file is writable, remove the
	// zone from the config FIRST (so a running daemon can't re-adopt it next cycle), then
	// clear state. On a state-save failure, restore the config entry so the two stay
	// consistent. Keys are never deleted — a DS at the registrar may still reference them.
	inConfig := false
	if _, ok := cfg.Zones[domain]; ok {
		inConfig = true
		if err := preflightConfigAppend(configPath); err != nil {
			return fmt.Errorf("config file %s not writable (needed to remove the zone entry): %w", configPath, err)
		}
		if err := RemoveZoneFromConfigFile(configPath, domain); err != nil && err != errZoneNotInConfig {
			return fmt.Errorf("removing zone from config file: %w", err)
		}
	}

	state.RemoveZone(domain)
	if err := state.Save(); err != nil {
		if inConfig {
			if aerr := AddZoneToConfigFile(configPath, domain, zonePath); aerr != nil {
				slog.Error("[CLI] Rollback: failed to restore config entry after state-save failure",
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

	rollover := NewRolloverManager(cfg, state)
	if err := rollover.StartKSKRollover(domain); err != nil {
		return fmt.Errorf("starting rollover: %w", err)
	}

	// Sign with both keys
	signer := NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		return fmt.Errorf("signing zone: %w", err)
	}

	if err := state.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	runPostSignHook(cfg, domain, zoneState.Path)

	// Print new DS
	fmt.Printf("KSK rollover started for %s.\n\n", domain)
	fmt.Println("Both keys are now in the zone. Add the NEW DS record at your registrar:")
	keyGen := NewKeyGenerator(cfg)
	kskKey, err := keyGen.LoadPublicKey(domain, "ksk")
	if err != nil {
		return fmt.Errorf("loading new KSK for DS: %w", err)
	}
	fmt.Println(FormatDSRecordsFromKey(domain, kskKey))
	fmt.Printf("\nOnce the new DS is published, run: dnssec-tudor rollover complete %s\n", domain)

	maybeAutoPublishDS(cfg, state, domain, "rollover_start")

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

// runRolloverComplete finalizes a KSK or algorithm rollover
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

	rolloverMgr := NewRolloverManager(cfg, state)

	switch zoneState.Rollover.Type {
	case "ksk":
		slog.Info("[CLI] Completing KSK rollover", "domain", domain)
		if err := rolloverMgr.CompleteKSKRollover(domain); err != nil {
			return fmt.Errorf("completing KSK rollover: %w", err)
		}
		fmt.Printf("KSK rollover completed for %s.\n", domain)
		fmt.Println("You may now remove the OLD DS record from your registrar.")

	case "algorithm":
		slog.Info("[CLI] Completing algorithm rollover", "domain", domain)
		if err := rolloverMgr.CompleteAlgorithmRollover(domain); err != nil {
			return fmt.Errorf("completing algorithm rollover: %w", err)
		}
		fmt.Printf("Algorithm rollover completed for %s.\n", domain)
		fmt.Println("You may now remove the OLD DS record (old algorithm) from your registrar.")

	default:
		return fmt.Errorf("cannot complete rollover type %q manually", zoneState.Rollover.Type)
	}

	// Re-sign without old keys
	signer := NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		return fmt.Errorf("signing zone: %w", err)
	}

	if err := state.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	runPostSignHook(cfg, domain, zoneState.Path)

	maybeAutoPublishDS(cfg, state, domain, "rollover_complete")

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

	rolloverMgr := NewRolloverManager(cfg, state)
	if err := rolloverMgr.StartAlgorithmRollover(domain, targetAlgorithm); err != nil {
		return fmt.Errorf("starting algorithm rollover: %w", err)
	}

	// Re-sign with both algorithms
	signer := NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		return fmt.Errorf("signing zone: %w", err)
	}

	if err := state.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	runPostSignHook(cfg, domain, zoneState.Path)

	// Get new DS record
	keyGen := NewKeyGenerator(cfg)
	ksk, err := keyGen.LoadPublicKey(domain, "ksk")
	if err != nil {
		return fmt.Errorf("loading new KSK: %w", err)
	}

	ds := ComputeDS(domain, ksk, 2) // SHA-256 digest

	fmt.Printf("Algorithm rollover started for %s.\n", domain)
	fmt.Printf("Old algorithm: %s\n", state.GetZone(domain).Rollover.OldAlgorithm)
	fmt.Printf("New algorithm: %s\n\n", targetAlgorithm)
	fmt.Println("Add the following DS record to your registrar:")
	fmt.Println()
	fmt.Println(ds.String())
	fmt.Println()
	fmt.Printf("After the new DS propagates, run: dnssec-tudor rollover complete %s\n", domain)

	maybeAutoPublishDS(cfg, state, domain, "rollover_start")

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
	keyGen := NewKeyGenerator(cfg)
	ksk, err := keyGen.LoadPublicKey(domain, "ksk")
	if err != nil {
		return fmt.Errorf("loading KSK: %w", err)
	}

	if jsonOutput {
		ds := ComputeDS(domain, ksk, dns.SHA256)
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

	dsOutput := FormatDSRecordsFromKey(domain, ksk)
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
	keyGen := NewKeyGenerator(cfg)
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

	dnskeyOutput := FormatDNSKEYRecordsFromKeys(domain, ksk, zsk)
	fmt.Println(dnskeyOutput)
	return nil
}

// runImport imports existing BIND-style keys
func runImport(cmd *cobra.Command, args []string) error {
	domain := args[0]
	zonePath := args[1]
	kskPath, _ := cmd.Flags().GetString("ksk")
	zskPath, _ := cmd.Flags().GetString("zsk")

	if err := ValidateDomainName(domain); err != nil {
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
	if err := ValidateZoneFile(domain, zonePath); err != nil {
		return fmt.Errorf("invalid zone file: %w", err)
	}

	// Check domain not already managed
	if _, ok := cfg.Zones[domain]; ok {
		return fmt.Errorf("domain %q is already in config file", domain)
	}
	if state.GetZone(domain) != nil {
		return fmt.Errorf("domain %q is already managed (in state.json)", domain)
	}

	slog.Info("[CLI] Importing keys for domain", "domain", domain, "ksk", kskPath, "zsk", zskPath)

	// Read and validate KSK
	ksk, kskPriv, err := loadBindKeyPair(kskPath)
	if err != nil {
		return fmt.Errorf("loading KSK from %s: %w", kskPath, err)
	}
	if ksk.Flags != 257 {
		return fmt.Errorf("KSK has wrong flags %d (expected 257 for KSK)", ksk.Flags)
	}

	// Read and validate ZSK
	zsk, zskPriv, err := loadBindKeyPair(zskPath)
	if err != nil {
		return fmt.Errorf("loading ZSK from %s: %w", zskPath, err)
	}
	if zsk.Flags != 256 {
		return fmt.Errorf("ZSK has wrong flags %d (expected 256 for ZSK)", zsk.Flags)
	}

	// Verify algorithms match (or warn if they don't)
	if ksk.Algorithm != zsk.Algorithm {
		slog.Warn("[CLI] KSK and ZSK have different algorithms",
			"ksk_algorithm", AlgorithmName(ksk.Algorithm),
			"zsk_algorithm", AlgorithmName(zsk.Algorithm))
	}

	// Preflight the config append before writing any key material (R-023, mirroring add):
	// fail now if the config file isn't writable, rather than after converting keys and
	// signing, which would leave state and config diverged with retry blocked.
	if err := preflightConfigAppend(configPath); err != nil {
		return fmt.Errorf("config file %s not writable (needed to register the imported zone): %w", configPath, err)
	}

	// Save keys in our format
	keyGen := NewKeyGenerator(cfg)
	if err := keyGen.saveKeyFiles(domain, "ksk", ksk, kskPriv); err != nil {
		return fmt.Errorf("saving KSK: %w", err)
	}
	if err := keyGen.saveKeyFiles(domain, "zsk", zsk, zskPriv); err != nil {
		return fmt.Errorf("saving ZSK: %w", err)
	}

	// Create zone state
	now := time.Now().UTC()
	kskLifetime := cfg.GetZoneKSKLifetime(domain)
	zskLifetime := cfg.GetZoneZSKLifetime(domain)

	zoneState := &ZoneState{
		Path: zonePath,
		KSK: &KeyState{
			ID:          ksk.KeyTag(),
			Algorithm:   AlgorithmName(ksk.Algorithm),
			Created:     now, // We don't know the original creation time
			Expires:     now.Add(kskLifetime),
			RolloverDue: now.Add(time.Duration(float64(kskLifetime) * 0.75)),
		},
		ZSK: &KeyState{
			ID:          zsk.KeyTag(),
			Algorithm:   AlgorithmName(zsk.Algorithm),
			Created:     now,
			Expires:     now.Add(zskLifetime),
			RolloverDue: now.Add(time.Duration(float64(zskLifetime) * 0.75)),
		},
	}
	state.SetZone(domain, zoneState)

	// Add to in-memory config
	cfg.Zones[domain] = ZoneConfig{Path: zonePath}

	// Sign the zone
	signer := NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		state.RemoveZone(domain)
		return fmt.Errorf("signing zone: %w", err)
	}

	// Save state first — if this fails, config file is untouched
	if err := state.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	// Config file is written last — state is already consistent. If it fails despite the
	// preflight (e.g. a race), unwind the state so it doesn't diverge from config and a
	// retry isn't blocked at "already managed". Converted key files are left in place (a
	// registrar DS may reference them) with a note (R-023).
	if err := AddZoneToConfigFile(configPath, domain, zonePath); err != nil {
		state.RemoveZone(domain)
		if serr := state.Save(); serr != nil {
			slog.Error("[CLI] Rollback: failed to remove zone from state after config-append failure",
				"domain", domain, "error", serr)
		}
		signedPath := filepath.Join(cfg.OutputDir, domain+".zone.signed")
		if rerr := os.Remove(signedPath); rerr != nil && !os.IsNotExist(rerr) {
			slog.Warn("[CLI] Rollback: failed to remove signed zone", "path", signedPath, "error", rerr)
		}
		fmt.Fprintf(os.Stderr, "note: converted key files for %s were left in %s (a registrar DS may reference them); re-run import after fixing the config file\n", domain, cfg.KeysDir())
		return fmt.Errorf("adding zone to config file: %w", err)
	}

	fmt.Printf("\nDomain %s imported successfully.\n", domain)
	fmt.Printf("  KSK: %d (%s)\n", ksk.KeyTag(), AlgorithmName(ksk.Algorithm))
	fmt.Printf("  ZSK: %d (%s)\n", zsk.KeyTag(), AlgorithmName(zsk.Algorithm))
	fmt.Printf("  Config updated: %s\n", configPath)
	fmt.Printf("  Signed zone:    %s\n\n", filepath.Join(cfg.OutputDir, domain+".zone.signed"))
	fmt.Println("DS record (verify this matches what's at your registrar):")
	dsOutput := FormatDSRecordsFromKey(domain, ksk)
	fmt.Println(dsOutput)
	fmt.Println("Note: a running daemon picks up the new zone after SIGHUP (config reload).")

	runPostSignHook(cfg, domain, zonePath)

	return nil
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
	dnskey, err := parseDNSKEYFromFile(string(keyData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", keyFile, err)
	}

	// Read private key
	privFile := basePath + ".private"
	privData, err := os.ReadFile(privFile)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", privFile, err)
	}

	privateKey, err := parsePrivateKeyFromFile(string(privData))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %s: %w", privFile, err)
	}

	// Validate the imported pair before it is ever written or signed with (R-010): a
	// 32-byte-seed ED25519 key is accepted here, and a mismatched .key/.private pair is
	// rejected up front rather than panicking or emitting a bogus zone at sign time.
	if err := verifyKeyPairCorrespondence(dnskey, privateKey); err != nil {
		return nil, nil, fmt.Errorf("validating key pair at %s: %w", basePath, err)
	}

	return dnskey, privateKey, nil
}
