package password

import (
	"strings"
	"sync"
	"testing"
)

func TestHasher_HashAndVerify(t *testing.T) {
	cfg := DefaultConfig()
	// Use lighter parameters for fast unit tests
	cfg.MemoryKiB = 19456
	cfg.Iterations = 1
	cfg.Parallelism = 1

	hasher, err := NewHasher(cfg)
	if err != nil {
		t.Fatalf("failed to create hasher: %v", err)
	}

	pass := "CorrectHorseBatteryStaple123!"
	phc, err := hasher.Hash(pass)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	if !strings.HasPrefix(phc, "$argon2id$v=19$m=") {
		t.Errorf("expected valid argon2id PHC prefix, got %q", phc)
	}

	// Verify correct password
	match, needsRehash, err := hasher.Verify(pass, phc)
	if err != nil {
		t.Fatalf("verify returned unexpected error: %v", err)
	}
	if !match {
		t.Error("expected password to match")
	}
	if needsRehash {
		t.Error("expected needsRehash=false for current config")
	}

	// Verify incorrect password
	wrongMatch, _, err := hasher.Verify("WrongPassword456!", phc)
	if err != nil {
		t.Fatalf("verify returned unexpected error: %v", err)
	}
	if wrongMatch {
		t.Error("expected wrong password to fail match")
	}
}

func TestHasher_PolicyValidation(t *testing.T) {
	// Too short (< 12)
	_, err := ValidatePolicy("short123")
	if err != ErrPasswordTooShort {
		t.Errorf("expected ErrPasswordTooShort, got %v", err)
	}

	// Too long (> 128)
	oversized := strings.Repeat("A", 129)
	_, err = ValidatePolicy(oversized)
	if err != ErrPasswordTooLong {
		t.Errorf("expected ErrPasswordTooLong, got %v", err)
	}

	// Breached password
	_, err = ValidatePolicy("password1234")
	if err != ErrPasswordBreached {
		t.Errorf("expected ErrPasswordBreached, got %v", err)
	}

	// Valid password
	valid, err := ValidatePolicy("ValidSecurePass123!")
	if err != nil {
		t.Errorf("expected clean policy validation, got %v", err)
	}
	if valid != "ValidSecurePass123!" {
		t.Errorf("unexpected normalized string: %q", valid)
	}
}

func TestHasher_UnicodeNFKC(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MemoryKiB = 19456
	cfg.Iterations = 1
	cfg.Parallelism = 1

	hasher, err := NewHasher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// "café" with composed 'é' vs decomposed 'e' + combining acute accent
	passNFC := "caf\u00e9Passphrase123"
	passNFD := "cafe\u0301Passphrase123"

	phc, err := hasher.Hash(passNFC)
	if err != nil {
		t.Fatal(err)
	}

	match, _, err := hasher.Verify(passNFD, phc)
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("expected NFC and NFD representations to verify identically under NFKC normalization")
	}
}

func TestHasher_DummyVerification(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MemoryKiB = 19456
	cfg.Iterations = 1
	cfg.Parallelism = 1

	hasher, err := NewHasher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Calling VerifyDummy should not panic and should simulate constant-time work
	hasher.VerifyDummy("UnknownUserPasswordAttempt123!")
}

func TestHasher_ConcurrencyThrottle(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MemoryKiB = 19456
	cfg.Iterations = 1
	cfg.Parallelism = 1
	cfg.MaxConcurrent = 2

	hasher, err := NewHasher(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var busyCount int
	var mu sync.Mutex

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := hasher.Hash("ConcurrentTestPassword123!")
			if err == ErrBusy {
				mu.Lock()
				busyCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	// Saturated calls must be handled without crash or unbounded memory growth
	t.Logf("Total busy throttled calls: %d", busyCount)
}
