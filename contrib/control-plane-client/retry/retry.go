package retry

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/config"
	"github.com/cilium/tetragon/contrib/control-plane-client/logger"
)

type Retryer struct {
	config config.RetryConfig
	logger logger.Logger
}

func NewRetryer(cfg config.RetryConfig, log logger.Logger) *Retryer {
	return &Retryer{
		config: cfg,
		logger: log,
	}
}

// secureRandom generates a cryptographically secure random float64 [0.0, 1.0)
func secureRandom() float64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to time-based if crypto/rand fails
		return float64(time.Now().UnixNano()%1000) / 1000.0
	}
	// Convert bytes to uint64, then to float64 in range [0, 1)
	return float64(binary.BigEndian.Uint64(b[:])&((1<<53)-1)) / float64(1<<53)
}

type RetryFunc func(ctx context.Context) error

func (r *Retryer) Do(ctx context.Context, fn RetryFunc) error {
	var lastErr error

	for attempt := 0; attempt < r.config.MaxAttempts; attempt++ {
		// Check context before each attempt
		select {
		case <-ctx.Done():
			r.logger.Debug("context cancelled/expired before attempt %d", attempt+1)
			return ctx.Err()
		default:
		}

		r.logger.Debug("attempt %d/%d", attempt+1, r.config.MaxAttempts)

		// Create child context with timeout for this specific attempt
		attemptCtx, cancel := context.WithTimeout(ctx, r.config.InitialBackoff*10)
		err := fn(attemptCtx)
		cancel()

		if err == nil {
			if attempt > 0 {
				r.logger.Debug("succeeded on attempt %d/%d", attempt+1, r.config.MaxAttempts)
			}
			return nil
		}

		lastErr = err

		if attempt == r.config.MaxAttempts-1 {
			r.logger.Debug("final attempt failed: %v", err)
			break
		}

		backoff := r.calculateBackoff(attempt)
		r.logger.Debug("attempt %d failed: %v. Retrying in %v...", attempt+1, err, backoff)

		// Use timer instead of time.After to be more context-aware
		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
			// Backoff completed, continue to next attempt
		case <-ctx.Done():
			timer.Stop()
			r.logger.Debug("context cancelled during backoff")
			return ctx.Err()
		}
	}

	return fmt.Errorf("max retry attempts (%d) exceeded: %w", r.config.MaxAttempts, lastErr)
}

func (r *Retryer) calculateBackoff(attempt int) time.Duration {
	backoff := float64(r.config.InitialBackoff) * math.Pow(r.config.BackoffMultiplier, float64(attempt))

	if backoff > float64(r.config.MaxBackoff) {
		r.logger.Debug("backoff capped at max: %v (calculated: %v)", r.config.MaxBackoff, time.Duration(backoff))
		backoff = float64(r.config.MaxBackoff)
	}

	jitterFactor := 0.5 + secureRandom()*0.5
	jitter := backoff * jitterFactor

	r.logger.Debug("backoff calculation: base=%v, multiplier=%.2f, attempt=%d, result=%v (jitter factor: %.2f)",
		r.config.InitialBackoff, r.config.BackoffMultiplier, attempt, time.Duration(jitter), jitterFactor)

	return time.Duration(jitter)
}

func (r *Retryer) IsRetryableHTTPCode(code int) bool {
	for _, retryableCode := range r.config.RetryableHTTPCodes {
		if code == retryableCode {
			return true
		}
	}
	return false
}

type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

type RetryFuncHTTP func(ctx context.Context) (int, error)

func (r *Retryer) DoHTTP(ctx context.Context, fn RetryFuncHTTP) error {
	return r.Do(ctx, func(ctx context.Context) error {
		statusCode, err := fn(ctx)
		if err != nil {
			if statusCode > 0 && !r.IsRetryableHTTPCode(statusCode) {
				r.logger.Debug("HTTP %d is not retryable, aborting retry loop", statusCode)
				return &NonRetryableError{Err: &HTTPError{StatusCode: statusCode, Message: err.Error()}}
			}
			if statusCode > 0 {
				r.logger.Debug("HTTP %d is retryable, will retry", statusCode)
			}
			return err
		}
		return nil
	})
}

type NonRetryableError struct {
	Err error
}

func (e *NonRetryableError) Error() string {
	return fmt.Sprintf("non-retryable error: %v", e.Err)
}

func (e *NonRetryableError) Unwrap() error {
	return e.Err
}
