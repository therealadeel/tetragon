package errors

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeAPI      ErrorType = "api_error"
	ErrorTypeConfig   ErrorType = "config_error"
	ErrorTypeTetragon ErrorType = "tetragon_error"
	ErrorTypePolicy   ErrorType = "policy_error"
	ErrorTypeRetry    ErrorType = "retry_error"
	ErrorTypeAuth     ErrorType = "auth_error"
	ErrorTypeNetwork  ErrorType = "network_error"
	ErrorTypeMetadata ErrorType = "metadata_error"
)

// ControlPlaneError represents a typed error with context
type ControlPlaneError struct {
	Type       ErrorType
	Message    string
	Err        error
	StatusCode int               // HTTP status code if applicable
	Fields     map[string]string // Additional context fields
}

func (e *ControlPlaneError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

func (e *ControlPlaneError) Unwrap() error {
	return e.Err
}

func (e *ControlPlaneError) WithField(key, value string) *ControlPlaneError {
	if e.Fields == nil {
		e.Fields = make(map[string]string)
	}
	e.Fields[key] = value
	return e
}

// NewError creates a new typed error
func NewError(errorType ErrorType, message string, err error) *ControlPlaneError {
	return &ControlPlaneError{
		Type:    errorType,
		Message: message,
		Err:     err,
		Fields:  make(map[string]string),
	}
}

// NewAPIError creates an API-related error with HTTP status code
func NewAPIError(message string, statusCode int, err error) *ControlPlaneError {
	return &ControlPlaneError{
		Type:       ErrorTypeAPI,
		Message:    message,
		StatusCode: statusCode,
		Err:        err,
		Fields:     make(map[string]string),
	}
}

// NewConfigError creates a configuration error
func NewConfigError(message string, err error) *ControlPlaneError {
	return NewError(ErrorTypeConfig, message, err)
}

// NewTetragonError creates a Tetragon-related error
func NewTetragonError(message string, err error) *ControlPlaneError {
	return NewError(ErrorTypeTetragon, message, err)
}

// NewPolicyError creates a policy-related error
func NewPolicyError(message string, err error) *ControlPlaneError {
	return NewError(ErrorTypePolicy, message, err)
}

// NewAuthError creates an authentication error
func NewAuthError(message string, err error) *ControlPlaneError {
	return NewError(ErrorTypeAuth, message, err)
}

// NewNetworkError creates a network-related error
func NewNetworkError(message string, err error) *ControlPlaneError {
	return NewError(ErrorTypeNetwork, message, err)
}

// IsRetryable determines if an error should be retried
func IsRetryable(err error) bool {
	var cpErr *ControlPlaneError
	if errors.As(err, &cpErr) {
		// Network errors are retryable
		if cpErr.Type == ErrorTypeNetwork {
			return true
		}

		// API errors with specific status codes are retryable
		if cpErr.Type == ErrorTypeAPI {
			return isRetryableStatusCode(cpErr.StatusCode)
		}

		// Retry errors are obviously retryable
		if cpErr.Type == ErrorTypeRetry {
			return true
		}
	}

	return false
}

// isRetryableStatusCode checks if an HTTP status code is retryable
func isRetryableStatusCode(statusCode int) bool {
	retryableCodes := []int{
		http.StatusRequestTimeout,      // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout,      // 504
	}

	for _, code := range retryableCodes {
		if statusCode == code {
			return true
		}
	}

	return false
}

// GetStatusCode extracts HTTP status code from error if available
func GetStatusCode(err error) int {
	var cpErr *ControlPlaneError
	if errors.As(err, &cpErr) {
		return cpErr.StatusCode
	}
	return 0
}
