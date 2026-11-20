package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalidCode   = errors.New("invalid TOTP code")
	ErrReplayedOTP   = errors.New("TOTP code has already been used in this window")
	ErrInvalidSecret = errors.New("invalid base32 TOTP secret")
)

const (
	defaultPeriod = 30
	defaultDigits = 6
)

// GenerateSecret generates a secure random 160-bit (20-byte) base32 secret.
func GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// BuildOTPAuthURL creates a standard otpauth:// URL for authenticator apps.
func BuildOTPAuthURL(issuer, accountName, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")

	label := url.PathEscape(issuer + ":" + accountName)
	return fmt.Sprintf("otpauth://totp/%s?%s", label, v.Encode())
}

// ComputeCode generates a 6-digit TOTP code for a given timestamp.
func ComputeCode(secret string, t time.Time) (string, int64, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", 0, err
	}

	step := t.Unix() / defaultPeriod
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(step))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	// Dynamic truncation per RFC 4226 Section 5.3
	offset := h[len(h)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(h[offset : offset+4])
	binaryCode &= 0x7fffffff

	code := binaryCode % 1000000
	return fmt.Sprintf("%06d", code), step, nil
}

// VerifyCode verifies a user-provided 6-digit code against secret.
// Enforces RFC 6238 Section 5.2 replay protection: the code step must be strictly greater than lastUsedStep.
func VerifyCode(secret, code string, lastUsedStep int64, now time.Time) (int64, error) {
	code = strings.TrimSpace(code)
	if len(code) != defaultDigits {
		return 0, ErrInvalidCode
	}

	key, err := decodeSecret(secret)
	if err != nil {
		return 0, err
	}

	currentStep := now.Unix() / defaultPeriod

	// Window check: -1, 0, +1 step
	for _, step := range []int64{currentStep, currentStep - 1, currentStep + 1} {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(step))

		mac := hmac.New(sha1.New, key)
		mac.Write(buf)
		h := mac.Sum(nil)

		offset := h[len(h)-1] & 0x0f
		binaryCode := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
		expectedCode := fmt.Sprintf("%06d", binaryCode%1000000)

		if subtle.ConstantTimeCompare([]byte(code), []byte(expectedCode)) == 1 {
			// RFC 6238 §5.2 Replay Protection: MUST NOT accept same code twice
			if step <= lastUsedStep {
				return 0, ErrReplayedOTP
			}
			return step, nil
		}
	}

	return 0, ErrInvalidCode
}

// RecoveryCode holds plaintext and hashed representations of a backup recovery code.
type RecoveryCode struct {
	Plain  string
	Hashed string
}

// GenerateRecoveryCodes produces 8 random, single-use recovery codes.
func GenerateRecoveryCodes() ([]RecoveryCode, error) {
	codes := make([]RecoveryCode, 8)
	for i := 0; i < 8; i++ {
		raw := make([]byte, 5)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		plain := fmt.Sprintf("%04x-%04x", binary.BigEndian.Uint16(raw[0:2]), binary.BigEndian.Uint16(raw[2:4]))
		hash := sha256.Sum256([]byte(plain))
		codes[i] = RecoveryCode{
			Plain:  plain,
			Hashed: fmt.Sprintf("%x", hash),
		}
	}
	return codes, nil
}

// VerifyRecoveryCode checks a recovery code against stored hashes in constant time.
func VerifyRecoveryCode(plainCode string, storedHashes []string) (int, bool) {
	plainCode = strings.TrimSpace(plainCode)
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(plainCode)))

	matchedIdx := -1
	for i, h := range storedHashes {
		if subtle.ConstantTimeCompare([]byte(hash), []byte(h)) == 1 {
			matchedIdx = i
		}
	}

	if matchedIdx >= 0 {
		return matchedIdx, true
	}
	return -1, false
}

func decodeSecret(secret string) ([]byte, error) {
	clean := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean)
	if err != nil {
		// Fallback to padded decoding
		decoded, err = base32.StdEncoding.DecodeString(clean)
		if err != nil {
			return nil, ErrInvalidSecret
		}
	}
	return decoded, nil
}
