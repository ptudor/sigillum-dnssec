package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ptudor/dnssec-validator/internal/config"
)

var (
	// reqIDCounter is a process-local monotonic counter used only when crypto/rand
	// is unavailable, guaranteeing the fallback IDs are unique within the process.
	reqIDCounter atomic.Uint64
	// reqIDSeed differs per process so fallback IDs from distinct processes do not
	// collide. Derived from the PID and start time (no client data, no secrets).
	reqIDSeed     = uint32(os.Getpid())
	reqIDWarnOnce sync.Once
)

// GenerateRequestID creates a unique request ID for tracing.
func GenerateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// R-056: crypto/rand failed — do NOT hex-encode the zero/partial buffer,
		// which repeats identical IDs across requests. Build a deterministic,
		// process-local, collision-free ID from a monotonic counter mixed with a
		// per-process seed and the clock, in the same 16-hex-char shape. No client
		// data or secrets are included.
		n := reqIDCounter.Add(1)
		reqIDWarnOnce.Do(func() {
			slog.Warn("crypto/rand unavailable for request IDs; using deterministic counter fallback", "error", err.Error())
		})
		return formatFallbackRequestID(n)
	}
	return hex.EncodeToString(b)
}

// formatFallbackRequestID renders the deterministic fallback ID (R-056): a
// per-process seed mixed with the clock, plus the monotonic counter, in the same
// 16-hex-char shape as the crypto/rand path. The counter guarantees uniqueness
// within the process regardless of clock resolution.
func formatFallbackRequestID(n uint64) string {
	return fmt.Sprintf("%08x%08x", reqIDSeed^uint32(time.Now().Unix()), uint32(n))
}

// logFile holds the log file handle for cleanup
var logFile *os.File

// SetupLogging configures the global slog logger based on configuration
func SetupLogging(cfg *config.Config) error {
	level := parseLogLevel(cfg.LogLevel)

	opts := &slog.HandlerOptions{
		Level: level,
	}

	// Determine output destination
	output := os.Stdout
	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file %s: %w", cfg.LogFile, err)
		}
		logFile = f
		output = f
	}

	var handler slog.Handler
	switch strings.ToLower(cfg.LogFormat) {
	case "json":
		handler = slog.NewJSONHandler(output, opts)
	default:
		handler = slog.NewTextHandler(output, opts)
	}

	slog.SetDefault(slog.New(handler))
	return nil
}

// CloseLogFile closes the log file if one was opened
func CloseLogFile() {
	if logFile != nil {
		logFile.Close()
	}
}

func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// LogStartup logs application startup
func LogStartup(version, buildTime string, cfg *config.Config) {
	slog.Info("[STARTUP]",
		"version", version,
		"build_time", buildTime,
		"listen_addr", cfg.ListenAddr,
		"log_level", cfg.LogLevel,
		"log_format", cfg.LogFormat,
	)
}

// LogShutdown logs application shutdown
func LogShutdown(reason string) {
	slog.Info("[SHUTDOWN]",
		"reason", reason,
	)
}

// LogError logs an error with context
func LogError(context string, err error, attrs ...any) {
	allAttrs := append([]any{"error", err.Error()}, attrs...)
	slog.Error(fmt.Sprintf("[%s]", strings.ToUpper(context)), allAttrs...)
}

// LogInfo logs an info message with context
func LogInfo(context string, msg string, attrs ...any) {
	slog.Info(fmt.Sprintf("[%s] %s", strings.ToUpper(context), msg), attrs...)
}

// LogDebug logs a debug message with context
func LogDebug(context string, msg string, attrs ...any) {
	slog.Debug(fmt.Sprintf("[%s] %s", strings.ToUpper(context), msg), attrs...)
}

// LogWarn logs a warning message with context
func LogWarn(context string, msg string, attrs ...any) {
	slog.Warn(fmt.Sprintf("[%s] %s", strings.ToUpper(context), msg), attrs...)
}

// LogValidation logs a DNSSEC validation event
func LogValidation(requestID, domain, status string, durationMs int64, attrs ...any) {
	allAttrs := append([]any{
		"request_id", requestID,
		"domain", domain,
		"status", status,
		"duration_ms", durationMs,
	}, attrs...)
	slog.Info("[VALIDATION]", allAttrs...)
}

// LogRequest logs an incoming HTTP request
func LogRequest(requestID, method, path, clientIP string, attrs ...any) {
	allAttrs := append([]any{
		"request_id", requestID,
		"method", method,
		"path", path,
		"client_ip", clientIP,
	}, attrs...)
	slog.Debug("[REQUEST]", allAttrs...)
}
