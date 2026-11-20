package mfa_test

import (
	"errors"
	"testing"
	"time"

	"github.com/raviteja-core/keystone/internal/auth/mfa"
)

func TestTOTP_GenerateAndVerify(t *testing.T) {
	secret, err := mfa.GenerateSecret()
	if err != nil {
		t.Fatalf("failed to generate secret: %v", err)
	}

	now := time.Now()
	code, step, err := mfa.ComputeCode(secret, now)
	if err != nil {
		t.Fatalf("failed to compute code: %v", err)
	}

	// 1. Initial verification -> success
	newStep, err := mfa.VerifyCode(secret, code, 0, now)
	if err != nil {
		t.Fatalf("expected verify success, got: %v", err)
	}
	if newStep != step {
		t.Errorf("expected step %d, got %d", step, newStep)
	}

	// 2. Replay of same code with updated lastUsedStep -> MUST FAIL
	_, err = mfa.VerifyCode(secret, code, newStep, now)
	if !errors.Is(err, mfa.ErrReplayedOTP) {
		t.Fatalf("CRITICAL SECURITY FLAW: replayed OTP code was accepted! Got: %v", err)
	}

	// 3. Incorrect code -> rejected
	_, err = mfa.VerifyCode(secret, "000000", 0, now)
	if !errors.Is(err, mfa.ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got: %v", err)
	}
}

func TestTOTP_WindowTolerance(t *testing.T) {
	secret, _ := mfa.GenerateSecret()
	now := time.Now()

	// Code from 29 seconds in past (step - 1 within tolerance)
	pastTime := now.Add(-29 * time.Second)
	codePast, _, _ := mfa.ComputeCode(secret, pastTime)

	step, err := mfa.VerifyCode(secret, codePast, 0, now)
	if err != nil {
		t.Fatalf("expected past window code to succeed: %v", err)
	}
	if step == 0 {
		t.Errorf("step should be non-zero")
	}

	// Code from 90 seconds in past (outside window) -> rejected
	tooOldTime := now.Add(-90 * time.Second)
	codeTooOld, _, _ := mfa.ComputeCode(secret, tooOldTime)
	_, err = mfa.VerifyCode(secret, codeTooOld, 0, now)
	if !errors.Is(err, mfa.ErrInvalidCode) {
		t.Errorf("expected code outside window to be rejected, got: %v", err)
	}
}

func TestTOTP_RecoveryCodes(t *testing.T) {
	codes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		t.Fatalf("failed to generate recovery codes: %v", err)
	}
	if len(codes) != 8 {
		t.Fatalf("expected 8 recovery codes, got %d", len(codes))
	}

	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = c.Hashed
	}

	// Verify valid code
	idx, ok := mfa.VerifyRecoveryCode(codes[3].Plain, hashes)
	if !ok || idx != 3 {
		t.Errorf("expected match at index 3, got idx=%d, ok=%v", idx, ok)
	}

	// Verify invalid code
	_, ok = mfa.VerifyRecoveryCode("invalid-code", hashes)
	if ok {
		t.Errorf("expected invalid code to fail")
	}
}
