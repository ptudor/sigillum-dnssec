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
	ErrTypeBadRequest          = "https://dnssec-validator.any53.com/errors/bad-request"
	ErrTypeForbidden           = "https://dnssec-validator.any53.com/errors/forbidden"
	ErrTypeNotFound            = "https://dnssec-validator.any53.com/errors/not-found"
	ErrTypeMethodNotAllowed    = "https://dnssec-validator.any53.com/errors/method-not-allowed"
	ErrTypeTooManyRequests     = "https://dnssec-validator.any53.com/errors/too-many-requests"
	ErrTypeInternalServerError = "https://dnssec-validator.any53.com/errors/internal-server-error"
	ErrTypeServiceUnavailable  = "https://dnssec-validator.any53.com/errors/service-unavailable"
	ErrTypeInvalidDomain       = "https://dnssec-validator.any53.com/errors/invalid-domain"
	ErrTypeValidationFailed    = "https://dnssec-validator.any53.com/errors/validation-failed"
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

// writeJSONError writes an RFC 7807 Problem Details error response (convenience wrapper)
func writeJSONError(w http.ResponseWriter, message string, status int) {
	// Map status code to error type and title
	var errType, title string
	switch status {
	case http.StatusBadRequest:
		errType = ErrTypeBadRequest
		title = "Bad Request"
	case http.StatusForbidden:
		errType = ErrTypeForbidden
		title = "Forbidden"
	case http.StatusNotFound:
		errType = ErrTypeNotFound
		title = "Not Found"
	case http.StatusMethodNotAllowed:
		errType = ErrTypeMethodNotAllowed
		title = "Method Not Allowed"
	case http.StatusTooManyRequests:
		errType = ErrTypeTooManyRequests
		title = "Too Many Requests"
	case http.StatusInternalServerError:
		errType = ErrTypeInternalServerError
		title = "Internal Server Error"
		message = "internal server error" // Mask internal error details
	case http.StatusServiceUnavailable:
		errType = ErrTypeServiceUnavailable
		title = "Service Unavailable"
	default:
		errType = ErrTypeInternalServerError
		title = "Error"
	}
	writeProblemDetails(w, errType, title, status, message, "")
}
