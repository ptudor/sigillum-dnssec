package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// SSEWriter writes Server-Sent Events to an HTTP response
type SSEWriter struct {
	w        http.ResponseWriter
	flusher  http.Flusher
	streamID string
}

// NewSSEWriter creates a new SSE writer
func NewSSEWriter(w http.ResponseWriter) (*SSEWriter, error) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, fmt.Errorf("streaming not supported")
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable reverse proxy buffering
	setSecurityHeaders(w)

	return &SSEWriter{
		w:       w,
		flusher: flusher,
	}, nil
}

// SetStreamID sets a per-stream SSE id that is emitted with every subsequent
// event. The browser echoes the most recently received id back in the
// Last-Event-ID request header when its EventSource auto-reconnects; stamping a
// stable per-request id lets the server detect and refuse that reconnect
// instead of silently re-running the whole validation (R-090).
func (s *SSEWriter) SetStreamID(id string) {
	s.streamID = id
}

// WriteEvent writes an SSE event with the given type and data
func (s *SSEWriter) WriteEvent(eventType string, data interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal event data: %w", err)
	}

	// Stamp the per-stream id (if any) so the client records it as
	// Last-Event-ID and echoes it on an auto-reconnect (R-090).
	if s.streamID != "" {
		if _, err := fmt.Fprintf(s.w, "id: %s\n", s.streamID); err != nil {
			return fmt.Errorf("failed to write event id: %w", err)
		}
	}

	// Write event type
	if _, err := fmt.Fprintf(s.w, "event: %s\n", eventType); err != nil {
		return fmt.Errorf("failed to write event type: %w", err)
	}

	// Write data
	if _, err := fmt.Fprintf(s.w, "data: %s\n\n", jsonData); err != nil {
		return fmt.Errorf("failed to write event data: %w", err)
	}

	s.flusher.Flush()
	return nil
}

// WriteRawEvent writes a raw SSE event
func (s *SSEWriter) WriteRawEvent(eventType, data string) error {
	if _, err := fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", eventType, data); err != nil {
		return fmt.Errorf("failed to write raw event: %w", err)
	}
	s.flusher.Flush()
	return nil
}

// WriteComment writes an SSE comment (for keep-alive)
func (s *SSEWriter) WriteComment(comment string) error {
	if _, err := fmt.Fprintf(s.w, ": %s\n\n", comment); err != nil {
		return fmt.Errorf("failed to write comment: %w", err)
	}
	s.flusher.Flush()
	return nil
}

// WriteRetry sets the reconnection time in milliseconds
func (s *SSEWriter) WriteRetry(ms int) error {
	if _, err := fmt.Fprintf(s.w, "retry: %d\n\n", ms); err != nil {
		return fmt.Errorf("failed to write retry: %w", err)
	}
	s.flusher.Flush()
	return nil
}

// WriteID sets the event ID for reconnection
func (s *SSEWriter) WriteID(id string) error {
	if _, err := fmt.Fprintf(s.w, "id: %s\n", id); err != nil {
		return fmt.Errorf("failed to write ID: %w", err)
	}
	s.flusher.Flush()
	return nil
}
