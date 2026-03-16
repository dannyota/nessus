package nessus

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrAuth       = errors.New("nessus: authentication failed")
	ErrNotFound   = errors.New("nessus: resource not found")
	ErrPermission = errors.New("nessus: insufficient permissions")
)

// APIError represents a non-2xx HTTP response from the Nessus scanner.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("nessus: API error %d: %s", e.StatusCode, e.Message)
}

// isCertificateError checks if err is a TLS/x509 certificate error.
func isCertificateError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "x509:") ||
		strings.Contains(s, "certificate") ||
		strings.Contains(s, "tls:")
}
