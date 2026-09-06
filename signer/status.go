package main

import (
	"encoding/json"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/validate"

	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// StatusOutput represents the JSON output for the status command.
type StatusOutput struct {
	Timestamp time.Time                    `json:"timestamp"`
	Zones     map[string]*ZoneStatusOutput `json:"zones"`
	Summary   StatusSummary                `json:"summary"`
}

// ZoneStatusOutput represents per-zone status in the output. It carries an
// optional *ValidationResult attached by the status/validate commands; that
// coupling to the validator is why the presentation DTOs live in the root
// package (above both state and validate) rather than in the state package.
type ZoneStatusOutput struct {
	Status          string                     `json:"status"`
	Serial          uint32                     `json:"serial,omitempty"`
	PublishedSerial uint32                     `json:"published_serial,omitempty"`
	LastSigned      time.Time                  `json:"last_signed,omitempty"`
	SignaturesExp   time.Time                  `json:"signatures_expire,omitempty"`
	KSK             *statepkg.KeyState         `json:"ksk,omitempty"`
	ZSK             *statepkg.KeyState         `json:"zsk,omitempty"`
	Rollover        *statepkg.RolloverState    `json:"rollover,omitempty"`
	Warnings        []string                   `json:"warnings,omitempty"`
	Errors          []string                   `json:"errors,omitempty"`
	Validation      *validate.ValidationResult `json:"validation,omitempty"`
}

// StatusSummary provides a summary of all zones.
type StatusSummary struct {
	Total          int `json:"total"`
	Healthy        int `json:"healthy"`
	ActionRequired int `json:"action_required"`
	Warning        int `json:"warning"`
	Errors         int `json:"errors"`
}

// buildStatusOutput converts a point-in-time state snapshot into the status
// DTO. This presentation layer sits above both state (persistence) and the
// validator, so ZoneStatusOutput can carry an optional *ValidationResult
// without state ever depending on the validator.
func buildStatusOutput(s *statepkg.State, configured ...string) *StatusOutput {
	output := &StatusOutput{
		Timestamp: time.Now().UTC(),
		Zones:     make(map[string]*ZoneStatusOutput),
	}
	zones := s.SnapshotZones()
	// RA6X-033: a configured zone with no state entry never initialized; it
	// is reported as an error rather than omitted from every count.
	for _, domain := range configured {
		if _, ok := zones[domain]; !ok {
			output.Zones[domain] = &ZoneStatusOutput{
				Status: "error",
				Errors: []string{statepkg.OpInit + ": configured but not initialized (no state entry yet)"},
			}
			output.Summary.Total++
			output.Summary.Errors++
		}
	}
	for domain, zc := range zones {
		status := zc.Status()
		output.Zones[domain] = &ZoneStatusOutput{
			Status:          status,
			Serial:          zc.Serial,
			PublishedSerial: zc.PublishedSerial,
			LastSigned:      zc.LastSigned,
			SignaturesExp:   zc.SignaturesExp,
			KSK:             zc.KSK,
			ZSK:             zc.ZSK,
			Rollover:        zc.Rollover,
			Warnings:        zc.Warnings,
			Errors:          zc.Errors,
		}
		output.Summary.Total++
		switch status {
		case "healthy":
			output.Summary.Healthy++
		case "action_required":
			output.Summary.ActionRequired++
		case "warning":
			output.Summary.Warning++
		case "error":
			output.Summary.Errors++
		}
	}
	return output
}

// statusJSON returns the status output as indented JSON.
func statusJSON(s *statepkg.State, configured ...string) ([]byte, error) {
	return json.MarshalIndent(buildStatusOutput(s, configured...), "", "  ")
}
