package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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

	// dnskey command
	dnskeyCmd := &cobra.Command{
		Use:   "dnskey <domain>",
		Short: "Print DNSKEY records for a domain",
		Args:  cobra.ExactArgs(1),
		RunE:  runDNSKEY,
	}

	// Add all commands
	rootCmd.AddCommand(versionCmd, serveCmd, signCmd, resignCmd, statusCmd, addCmd, removeCmd, rolloverCmd, dsCmd, dnskeyCmd)

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
		// Treat as file path
		f, err := os.OpenFile(logOutput, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open log file %s: %v, falling back to stderr\n", logOutput, err)
			handler = slog.NewTextHandler(os.Stderr, opts)
		} else {
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

	state, err := LoadState(cfg.StatePath())
	if err != nil {
		return nil, nil, fmt.Errorf("loading state: %w", err)
	}

	return cfg, state, nil
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
				slog.Info("[DAEMON] Received SIGHUP, reloading configuration")
				newCfg, err := LoadConfig(configPath)
				if err != nil {
					slog.Error("[DAEMON] Failed to reload config", "error", err)
					continue
				}
				daemon.Reload(newCfg)
			case syscall.SIGINT, syscall.SIGTERM:
				slog.Info("[DAEMON] Received shutdown signal", "signal", sig)
				daemon.Shutdown()
				return nil
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
	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	slog.Info("[CLI] Signing all zones", "count", len(cfg.Zones))

	signer := NewSigner(cfg, state)
	if err := signer.SignAll(); err != nil {
		return fmt.Errorf("signing failed: %w", err)
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

	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

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

	// Execute post-sign hook if configured
	if cfg.Hooks.PostSign != "" {
		slog.Info("[CLI] Executing post-sign hook", "command", cfg.Hooks.PostSign)
		hookEnv := &HookEnv{
			Domain:     domain,
			ZonePath:   zoneCfg.Path,
			SignedPath: fmt.Sprintf("%s/%s.zone.signed", cfg.OutputDir, domain),
			OutputDir:  cfg.OutputDir,
		}
		executeHook(cfg.Hooks.PostSign, hookEnv)
	}

	fmt.Printf("Zone %s re-signed successfully.\n", domain)
	fmt.Printf("Signed zone written to: %s/%s.zone.signed\n", cfg.OutputDir, domain)

	return nil
}

// runStatus prints the current status
func runStatus(cmd *cobra.Command, args []string) error {
	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	domain, _ := cmd.Flags().GetString("domain")
	if domain != "" {
		// Show status for specific domain
		zoneState := state.GetZone(domain)
		if zoneState == nil {
			return fmt.Errorf("domain %q not found in state", domain)
		}
		output := &ZoneStatusOutput{
			Status:        zoneState.Status(),
			Serial:        zoneState.Serial,
			LastSigned:    zoneState.LastSigned,
			SignaturesExp: zoneState.SignaturesExp,
			KSK:           zoneState.KSK,
			ZSK:           zoneState.ZSK,
			Rollover:      zoneState.Rollover,
			Warnings:      zoneState.Warnings,
			Errors:        zoneState.Errors,
		}
		jsonData, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling status: %w", err)
		}
		fmt.Println(string(jsonData))
		return nil
	}

	// Show status for all zones
	jsonData, err := state.ToJSON()
	if err != nil {
		return fmt.Errorf("generating status: %w", err)
	}
	fmt.Println(string(jsonData))
	_ = cfg // silence unused warning until fully implemented
	return nil
}

// runAdd adds a new domain
func runAdd(cmd *cobra.Command, args []string) error {
	domain := args[0]
	zonePath := args[1]

	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

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

	// Add zone to config file
	if err := AddZoneToConfigFile(configPath, domain, zonePath); err != nil {
		return fmt.Errorf("adding zone to config file: %w", err)
	}
	slog.Info("[CLI] Added zone to config file", "config", configPath)

	// Add to in-memory config so signing works
	cfg.Zones[domain] = ZoneConfig{Path: zonePath}

	// Generate keys
	keyGen := NewKeyGenerator(cfg)
	ksk, err := keyGen.GenerateKSK(domain)
	if err != nil {
		return fmt.Errorf("generating KSK: %w", err)
	}
	zsk, err := keyGen.GenerateZSK(domain)
	if err != nil {
		return fmt.Errorf("generating ZSK: %w", err)
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
		return fmt.Errorf("signing zone: %w", err)
	}

	// Save state
	if err := state.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	// Print DS records - load actual key for proper DS computation
	kskKey, _, err := keyGen.LoadKeyPair(domain, "ksk")
	if err != nil {
		return fmt.Errorf("loading KSK for DS: %w", err)
	}

	fmt.Printf("\nDomain %s added successfully.\n", domain)
	fmt.Printf("  Config updated: %s\n", configPath)
	fmt.Printf("  Signed zone:    %s/%s.zone.signed\n\n", cfg.OutputDir, domain)
	fmt.Println("Add the following DS record to your registrar:")
	dsOutput := FormatDSRecordsFromKey(domain, kskKey)
	fmt.Println(dsOutput)

	return nil
}

// runRemove removes a domain from management
func runRemove(cmd *cobra.Command, args []string) error {
	domain := args[0]

	_, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	if state.GetZone(domain) == nil {
		return fmt.Errorf("domain %q is not managed", domain)
	}

	slog.Info("[CLI] Removing domain from management", "domain", domain)
	state.RemoveZone(domain)

	if err := state.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	fmt.Printf("Domain %s removed from management.\n", domain)
	fmt.Printf("Note: Key files were NOT deleted.\n")
	fmt.Printf("Note: You should manually remove the zone from config.toml.\n")
	return nil
}

// runRolloverStart begins a KSK rollover
func runRolloverStart(cmd *cobra.Command, args []string) error {
	domain := args[0]

	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

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

	// Print new DS
	zoneState = state.GetZone(domain)
	fmt.Printf("KSK rollover started for %s.\n\n", domain)
	fmt.Println("Both keys are now in the zone. Add the NEW DS record at your registrar:")
	// Find the new KSK
	dsOutput, err := FormatDSRecords(domain, zoneState.KSK)
	if err != nil {
		return fmt.Errorf("formatting DS records: %w", err)
	}
	fmt.Println(dsOutput)
	fmt.Printf("\nOnce the new DS is published, run: dnssec-tudor rollover complete %s\n", domain)

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

	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

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

	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

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

	// Get new DS record
	keyGen := NewKeyGenerator(cfg)
	ksk, _, err := keyGen.LoadKeyPair(domain, "ksk")
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

	return nil
}

// runDS prints DS records for a domain
func runDS(cmd *cobra.Command, args []string) error {
	domain := args[0]

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

	// Load the actual key to compute DS
	keyGen := NewKeyGenerator(cfg)
	ksk, _, err := keyGen.LoadKeyPair(domain, "ksk")
	if err != nil {
		return fmt.Errorf("loading KSK: %w", err)
	}

	dsOutput := FormatDSRecordsFromKey(domain, ksk)
	fmt.Println(dsOutput)
	return nil
}

// runDNSKEY prints DNSKEY records for a domain
func runDNSKEY(cmd *cobra.Command, args []string) error {
	domain := args[0]

	cfg, state, err := loadConfigAndState()
	if err != nil {
		return err
	}

	zoneState := state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("domain %q is not managed", domain)
	}

	// Load the actual keys
	keyGen := NewKeyGenerator(cfg)
	var ksk, zsk *dns.DNSKEY

	if zoneState.KSK != nil {
		ksk, _, err = keyGen.LoadKeyPair(domain, "ksk")
		if err != nil {
			slog.Warn("[CLI] Failed to load KSK", "error", err)
		}
	}

	if zoneState.ZSK != nil {
		zsk, _, err = keyGen.LoadKeyPair(domain, "zsk")
		if err != nil {
			slog.Warn("[CLI] Failed to load ZSK", "error", err)
		}
	}

	dnskeyOutput := FormatDNSKEYRecordsFromKeys(domain, ksk, zsk)
	fmt.Println(dnskeyOutput)
	return nil
}
