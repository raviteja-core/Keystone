package ratelimit_test

import (
	"testing"
	"time"

	"github.com/raviteja-core/keystone/internal/platform/ratelimit"
)

func TestLimiter_SlidingWindow(t *testing.T) {
	limiter := ratelimit.NewLimiter(100*time.Millisecond, 3, 500*time.Millisecond)

	key := "client-ip-127.0.0.1"

	// 3 requests allowed within window
	if !limiter.Allow(key) {
		t.Errorf("expected request 1 to be allowed")
	}
	if !limiter.Allow(key) {
		t.Errorf("expected request 2 to be allowed")
	}
	if !limiter.Allow(key) {
		t.Errorf("expected request 3 to be allowed")
	}

	// 4th request in same window -> rejected
	if limiter.Allow(key) {
		t.Errorf("expected request 4 to be rejected by rate limit")
	}

	// After window passes -> allowed again
	time.Sleep(110 * time.Millisecond)
	if !limiter.Allow(key) {
		t.Errorf("expected request after window expiration to be allowed")
	}
}

func TestLimiter_AccountLockout(t *testing.T) {
	limiter := ratelimit.NewLimiter(time.Minute, 3, 200*time.Millisecond)
	userKey := "user-alice@example.com"

	limiter.RecordFailure(userKey)
	limiter.RecordFailure(userKey)
	locked, until := limiter.RecordFailure(userKey)

	if !locked {
		t.Fatalf("expected account to be locked out after 3 failures")
	}
	if until.Before(time.Now()) {
		t.Errorf("lockout timestamp must be in future")
	}

	// Request during lockout is blocked
	if limiter.Allow(userKey) {
		t.Errorf("request during lockout must be denied")
	}

	// Reset on success clears lockout
	limiter.Reset(userKey)
	if !limiter.Allow(userKey) {
		t.Errorf("request after reset must be allowed")
	}
}

func TestLimiter_Cleanup(t *testing.T) {
	limiter := ratelimit.NewLimiter(50*time.Millisecond, 2, 50*time.Millisecond)
	limiter.Allow("ephemeral-ip-1")
	limiter.Allow("ephemeral-ip-2")

	time.Sleep(60 * time.Millisecond)
	limiter.Cleanup()

	// Both expired keys are cleaned and fresh allowances granted
	if !limiter.Allow("ephemeral-ip-1") {
		t.Errorf("expected clean state after eviction")
	}
}
