package retry

import (
	"context"
	"fmt"
	"log"
	"math"
	"math/rand"
	"strings"
	"time"

	"github.com/cilium/tetragon/contrib/control-plane-client/config"
)

type Retryer struct {
	config   config.RetryConfig
	rng      *rand.Rand
	logLevel string
}

func NewRetryer(cfg config.RetryConfig) *Retryer {
	return &Retryer{
		config:   cfg,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
		logLevel: "",
	}
}

func NewRetryerWithLogLevel(cfg config.RetryConfig, logLevel string) *Retryer {
	return &Retryer{
		config:   cfg,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
		logLevel: strings.ToLower(logLevel),
	}
}

func (r *Retryer) isDebug() bool {
	return r.logLevel == "debug"
}

type RetryFunc func(ctx context.Context) error

func (r *Retryer) Do(ctx context.Context, fn RetryFunc) error {
	var lastErr error

	for attempt := 0; attempt < r.config.MaxAttempts; attempt++ {
		if ctx.Err() != nil {
			if r.isDebug() {
				log.Printf("[retry] Context cancelled/expired before attempt %d", attempt+1)
			}
			return ctx.Err()
		}

		if r.isDebug() {
			log.Printf("[retry] Attempt %d/%d", attempt+1, r.config.MaxAttempts)
		}

		err := fn(ctx)
		if err == nil {
			if r.isDebug() && attempt > 0 {
				log.Printf("[retry] Succeeded on attempt %d/%d", attempt+1, r.config.MaxAttempts)
			}
			return nil
		}

		lastErr = err

		if attempt == r.config.MaxAttempts-1 {
			if r.isDebug() {
				log.Printf("[retry] Final attempt failed: %v", err)
			}
			break
		}

		backoff := r.calculateBackoff(attempt)
		if r.isDebug() {
			log.Printf("[retry] Attempt %d failed: %v. Retrying in %v...", attempt+1, err, backoff)
		}

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			if r.isDebug() {
				log.Printf("[retry] Context cancelled during backoff")
			}
			return ctx.Err()
		}
	}

	return fmt.Errorf("max retry attempts (%d) exceeded: %w", r.config.MaxAttempts, lastErr)
}

func (r *Retryer) calculateBackoff(attempt int) time.Duration {
	backoff := float64(r.config.InitialBackoff) * math.Pow(r.config.BackoffMultiplier, float64(attempt))

	if backoff > float64(r.config.MaxBackoff) {
		if r.isDebug() {
			log.Printf("[retry] Backoff capped at max: %v (calculated: %v)", r.config.MaxBackoff, time.Duration(backoff))
		}
		backoff = float64(r.config.MaxBackoff)
	}

	jitterFactor := 0.5 + r.rng.Float64()*0.5
	jitter := backoff * jitterFactor

	if r.isDebug() {
		log.Printf("[retry] Backoff calculation: base=%v, multiplier=%.2f, attempt=%d, result=%v (jitter factor: %.2f)",
			r.config.InitialBackoff, r.config.BackoffMultiplier, attempt, time.Duration(jitter), jitterFactor)
	}

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
				if r.isDebug() {
					log.Printf("[retry] HTTP %d is not retryable, aborting retry loop", statusCode)
				}
				return &NonRetryableError{Err: &HTTPError{StatusCode: statusCode, Message: err.Error()}}
			}
			if r.isDebug() && statusCode > 0 {
				log.Printf("[retry] HTTP %d is retryable, will retry", statusCode)
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
