package client

import (
	"crypto/rand"
	"encoding/binary"
	"time"
)

// addJitter adds random jitter to a duration to prevent thundering herd
// Jitter range is ±20% of the base duration
func addJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}

	// Calculate jitter range (20% of base duration)
	jitterRange := float64(base) * 0.2

	// Get random value in range [-jitterRange, +jitterRange]
	randomFactor := (secureRandom() * 2.0) - 1.0 // Range: [-1.0, 1.0]
	jitter := time.Duration(randomFactor * jitterRange)

	result := base + jitter
	if result <= 0 {
		return base // Ensure we never return non-positive duration
	}

	return result
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

// calculateBackoffDuration calculates exponential backoff based on consecutive errors
// Returns the additional delay to add to the base interval
func calculateBackoffDuration(consecutiveErrors int, baseInterval time.Duration) time.Duration {
	if consecutiveErrors <= 0 {
		return 0
	}

	// Cap at 5 errors to prevent extremely long waits
	if consecutiveErrors > 5 {
		consecutiveErrors = 5
	}

	// Exponential backoff: 2^errors * baseInterval
	// e.g., 1 error = 2x, 2 errors = 4x, 3 errors = 8x, etc.
	multiplier := 1 << uint(consecutiveErrors) // 2^consecutiveErrors
	backoff := time.Duration(multiplier) * baseInterval

	// Cap backoff at 10 minutes
	maxBackoff := 10 * time.Minute
	if backoff > maxBackoff {
		backoff = maxBackoff
	}

	return backoff
}
