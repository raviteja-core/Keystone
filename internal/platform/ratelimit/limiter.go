package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter provides sliding-window rate limiting and temporary account lockout.
type Limiter struct {
	mu           sync.Mutex
	window       time.Duration
	maxAttempts  int
	lockDuration time.Duration
	records      map[string]*clientRecord
}

type clientRecord struct {
	attempts    []time.Time
	failedCount int
	lockedUntil time.Time
}

// NewLimiter creates a sliding window limiter.
func NewLimiter(window time.Duration, maxAttempts int, lockDuration time.Duration) *Limiter {
	return &Limiter{
		window:       window,
		maxAttempts:  maxAttempts,
		lockDuration: lockDuration,
		records:      make(map[string]*clientRecord),
	}
}

// Allow reports whether a request for the given key is permitted under the sliding window rate limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	rec, exists := l.records[key]
	if !exists {
		l.records[key] = &clientRecord{
			attempts: []time.Time{now},
		}
		return true
	}

	// Check if key is currently locked out
	if now.Before(rec.lockedUntil) {
		return false
	}

	// Prune attempts outside the sliding window
	threshold := now.Add(-l.window)
	validAttempts := make([]time.Time, 0, len(rec.attempts))
	for _, t := range rec.attempts {
		if t.After(threshold) {
			validAttempts = append(validAttempts, t)
		}
	}

	if len(validAttempts) >= l.maxAttempts {
		return false
	}

	validAttempts = append(validAttempts, now)
	rec.attempts = validAttempts
	return true
}

// RecordFailure records a failed authentication attempt and locks the key if threshold is exceeded.
func (l *Limiter) RecordFailure(key string) (bool, time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	rec, exists := l.records[key]
	if !exists {
		rec = &clientRecord{}
		l.records[key] = rec
	}

	rec.failedCount++
	if rec.failedCount >= l.maxAttempts {
		rec.lockedUntil = now.Add(l.lockDuration)
		return true, rec.lockedUntil
	}

	return false, time.Time{}
}

// Reset clears failure counts and lockout for a key (e.g. on successful login).
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, key)
}

// Cleanup evicts expired client records to prevent unbounded memory growth.
func (l *Limiter) Cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	threshold := now.Add(-l.window)

	for key, rec := range l.records {
		if now.Before(rec.lockedUntil) {
			continue
		}
		hasValid := false
		for _, t := range rec.attempts {
			if t.After(threshold) {
				hasValid = true
				break
			}
		}
		if !hasValid {
			delete(l.records, key)
		}
	}
}

// Middleware creates an HTTP middleware that rate limits requests based on client IP.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip = strings.TrimSpace(parts[0])
		}
		if host, _, err := net.SplitHostPort(ip); err == nil {
			ip = host
		}

		if !l.Allow(ip) {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(l.window.Seconds())))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limit_exceeded","error_description":"too many requests, please slow down"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
