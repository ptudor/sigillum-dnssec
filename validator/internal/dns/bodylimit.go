package dns

import (
	"errors"
	"fmt"
	"io"
)

// ErrResponseTooLarge marks an HTTP body that exceeds a loader's advertised
// maximum (RDAYBLUEX-034).
var ErrResponseTooLarge = errors.New("response body exceeds the maximum size")

// ReadBodyLimited reads at most limit bytes from r and fails when the body is
// larger than limit (RDAYBLUEX-034). Unlike a bare io.LimitReader, which
// silently truncates, it reads limit+1 bytes so an oversized body is
// rejected rather than parsed from its prefix; the body itself never enters
// the error.
func ReadBodyLimited(r io.Reader, limit int64, what string) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%s: invalid body limit %d", what, limit)
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: reading response body: %w", what, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: %w (limit %d bytes)", what, ErrResponseTooLarge, limit)
	}
	return data, nil
}
