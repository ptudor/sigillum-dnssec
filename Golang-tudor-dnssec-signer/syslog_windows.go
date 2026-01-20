//go:build windows

package main

import (
	"fmt"
	"log/slog"
)

// newSyslogHandler returns an error on Windows since syslog is not supported
func newSyslogHandler(level slog.Level) (slog.Handler, error) {
	return nil, fmt.Errorf("syslog is not supported on Windows")
}

// syslogSupported returns false on Windows
func syslogSupported() bool {
	return false
}
