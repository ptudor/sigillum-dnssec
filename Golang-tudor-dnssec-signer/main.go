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
		Short: "Finalize KSK rollover after DS update",
		Args:  cobra.ExactArgs(1),
		RunE:  runRolloverComplete,
	}

	rolloverCmd.AddCommand(rolloverStartCmd, rolloverStatusCmd, rolloverCompleteCmd)

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
	rootCmd.AddCommand(versionCmd, serveCmd, signCmd, statusCmd, addCmd, removeCmd, rolloverCmd, dsCmd, dnskeyCmd)

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
	if logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
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

	slog.Info("Starting dnssec-tudor daemon",
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
				slog.Info("Received SIGHUP, reloading configuration")
				newCfg, err := LoadConfig(configPath)
				if err != nil {
					slog.Error("Failed to reload config", "error", err)
					continue
				}
				daemon.Reload(newCfg)
			case syscall.SIGINT, syscall.SIGTERM:
				slog.Info("Received shutdown signal", "signal", sig)
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

	slog.Info("Signing all zones", "count", len(cfg.Zones))

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

	// Check domain not already managed
	if state.GetZone(domain) != nil {
		return fmt.Errorf("domain %q is already managed", domain)
	}

	slog.Info("Adding domain", "domain", domain, "path", zonePath)

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

	fmt.Printf("\nDomain %s added successfully.\n\n", domain)
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

	slog.Info("Removing domain from management", "domain", domain)
	state.RemoveZone(domain)

	if err := state.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	fmt.Printf("Domain %s removed from management.\nNote: Key files were NOT deleted.\n", domain)
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

	slog.Info("Starting KSK rollover", "domain", domain)

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

// runRolloverComplete finalizes a KSK rollover
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

	if zoneState.Rollover.Type != "ksk" {
		return fmt.Errorf("rollover in progress is not a KSK rollover (type: %s)", zoneState.Rollover.Type)
	}

	slog.Info("Completing KSK rollover", "domain", domain)

	rollover := NewRolloverManager(cfg, state)
	if err := rollover.CompleteKSKRollover(domain); err != nil {
		return fmt.Errorf("completing rollover: %w", err)
	}

	// Re-sign without old key
	signer := NewSigner(cfg, state)
	if err := signer.SignZone(domain); err != nil {
		return fmt.Errorf("signing zone: %w", err)
	}

	if err := state.Save(); err != nil {
		return fmt.Errorf("saving state: %w", err)
	}

	fmt.Printf("KSK rollover completed for %s.\n", domain)
	fmt.Println("You may now remove the OLD DS record from your registrar.")
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
			slog.Warn("Failed to load KSK", "error", err)
		}
	}

	if zoneState.ZSK != nil {
		zsk, _, err = keyGen.LoadKeyPair(domain, "zsk")
		if err != nil {
			slog.Warn("Failed to load ZSK", "error", err)
		}
	}

	dnskeyOutput := FormatDNSKEYRecordsFromKeys(domain, ksk, zsk)
	fmt.Println(dnskeyOutput)
	return nil
}
