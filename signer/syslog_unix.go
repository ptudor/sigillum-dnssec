//go:build !windows

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
)

// syslogHandler implements slog.Handler for syslog output
type syslogHandler struct {
	writer *syslog.Writer
	level  slog.Level
	attrs  []slog.Attr
	groups []string
}

// newSyslogHandler creates a new syslog handler. The returned io.Closer is the
// underlying syslog connection; setupLogging tracks it so a SIGHUP re-run can
// close the previous connection instead of leaking one fd per reload.
func newSyslogHandler(level slog.Level) (slog.Handler, io.Closer, error) {
	writer, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "dnssec-tudor")
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to syslog: %w", err)
	}
	return &syslogHandler{
		writer: writer,
		level:  level,
	}, writer, nil
}

func (h *syslogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *syslogHandler) Handle(_ context.Context, r slog.Record) error {
	// Build message with attributes
	msg := r.Message
	r.Attrs(func(a slog.Attr) bool {
		msg += fmt.Sprintf(" %s=%v", a.Key, a.Value)
		return true
	})
	for _, a := range h.attrs {
		msg += fmt.Sprintf(" %s=%v", a.Key, a.Value)
	}

	// Map slog levels to syslog priorities
	switch {
	case r.Level >= slog.LevelError:
		return h.writer.Err(msg)
	case r.Level >= slog.LevelWarn:
		return h.writer.Warning(msg)
	case r.Level >= slog.LevelInfo:
		return h.writer.Info(msg)
	default:
		return h.writer.Debug(msg)
	}
}

func (h *syslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &syslogHandler{
		writer: h.writer,
		level:  h.level,
		attrs:  newAttrs,
		groups: h.groups,
	}
}

func (h *syslogHandler) WithGroup(name string) slog.Handler {
	newGroups := make([]string, len(h.groups)+1)
	copy(newGroups, h.groups)
	newGroups[len(h.groups)] = name
	return &syslogHandler{
		writer: h.writer,
		level:  h.level,
		attrs:  h.attrs,
		groups: newGroups,
	}
}

// syslogSupported returns true on Unix systems
func syslogSupported() bool {
	return true
}
