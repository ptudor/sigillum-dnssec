package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// GenerateRequestID creates a unique request ID for tracing
func GenerateRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID if random fails
		return fmt.Sprintf("%x", b)
	}
	return hex.EncodeToString(b)
}

// SetupLogging configures the global slog logger based on configuration
func SetupLogging(cfg *Config) error {
	level := parseLogLevel(cfg.LogLevel)

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	switch strings.ToLower(cfg.LogFormat) {
	case "json":
		handler = slog.NewJSONHandler(os.Stdout, opts)
	default:
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	slog.SetDefault(slog.New(handler))
	return nil
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
func LogStartup(version, buildTime string, cfg *Config) {
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
