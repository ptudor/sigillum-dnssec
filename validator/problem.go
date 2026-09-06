package main

import (
	"encoding/json"
	"net/http"
)

// ProblemDetails implements RFC 7807 (Problem Details for HTTP APIs)
type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// Error type URIs for RFC 7807 responses
const (
	ErrTypeBadRequest          = "https://sigillum-validator.any53.com/errors/bad-request"
	ErrTypeForbidden           = "https://sigillum-validator.any53.com/errors/forbidden"
	ErrTypeNotFound            = "https://sigillum-validator.any53.com/errors/not-found"
	ErrTypeMethodNotAllowed    = "https://sigillum-validator.any53.com/errors/method-not-allowed"
	ErrTypeTooManyRequests     = "https://sigillum-validator.any53.com/errors/too-many-requests"
	ErrTypeInternalServerError = "https://sigillum-validator.any53.com/errors/internal-server-error"
	ErrTypeServiceUnavailable  = "https://sigillum-validator.any53.com/errors/service-unavailable"
	ErrTypeInvalidDomain       = "https://sigillum-validator.any53.com/errors/invalid-domain"
	ErrTypeValidationFailed    = "https://sigillum-validator.any53.com/errors/validation-failed"
)

// writeProblemDetails writes an RFC 7807 Problem Details error response
func writeProblemDetails(w http.ResponseWriter, errType, title string, status int, detail, instance string) {
	problem := ProblemDetails{
		Type:   errType,
		Title:  title,
		Status: status,
	}
	if detail != "" {
		problem.Detail = detail
	}
	if instance != "" {
		problem.Instance = instance
	}
	setSecurityHeaders(w)
	setNoStore(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(problem)
}
