//go:build windows

package main

import (
	"fmt"
	"io"
	"log/slog"
)

// newSyslogHandler returns an error on Windows since syslog is not supported.
// The io.Closer mirrors the Unix signature; it is always nil here.
func newSyslogHandler(level slog.Level) (slog.Handler, io.Closer, error) {
	return nil, nil, fmt.Errorf("syslog is not supported on Windows")
}

// syslogSupported returns false on Windows
func syslogSupported() bool {
	return false
}
