package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

var (
	ErrPasswordTooShort  = errors.New("password must be at least 12 characters long")
	ErrPasswordTooLong   = errors.New("password must not exceed 128 characters")
	ErrPasswordBreached  = errors.New("password is too common and cannot be used")
	ErrInvalidHashFormat = errors.New("invalid argon2id PHC hash format")
	ErrBusy              = errors.New("system busy: password hashing capacity reached")
)

// Common breached passwords to reject
var topBreachedPasswords = map[string]struct{}{
	"password1234": {},
	"123456789012": {},
	"qwertyuiop12": {},
	"changeme1234": {},
	"adminadmin12": {},
	"welcome12345": {},
	"letmein12345": {},
}

// Config holds Argon2id cost parameters.
type Config struct {
	MemoryKiB     uint32
	Iterations    uint32
	Parallelism   uint8
	KeyLength     uint32
	SaltLength    uint32
	MaxConcurrent int
}

// DefaultConfig provides standard OWASP-exceeding parameters.
func DefaultConfig() Config {
	return Config{
		MemoryKiB:     65536, // 64 MiB
		Iterations:    3,
		Parallelism:   2,
		KeyLength:     32,
		SaltLength:    16,
		MaxConcurrent: 4,
	}
}

// Hasher handles Argon2id hashing, verification, and timing attack defense.
type Hasher struct {
	cfg       Config
	sem       chan struct{}
	dummyHash string
}

// NewHasher initializes an Argon2id hasher with a precomputed dummy hash.
func NewHasher(cfg Config) (*Hasher, error) {
	if cfg.MemoryKiB < 19456 {
		return nil, errors.New("argon2 memory must be >= 19456 KiB (19 MiB)")
	}
	if cfg.Iterations < 1 {
		return nil, errors.New("argon2 iterations must be >= 1")
	}
	if cfg.Parallelism < 1 {
		return nil, errors.New("argon2 parallelism must be >= 1")
	}
	if cfg.SaltLength < 16 {
		cfg.SaltLength = 16
	}
	if cfg.KeyLength < 32 {
		cfg.KeyLength = 32
	}
	if cfg.MaxConcurrent < 1 {
		cfg.MaxConcurrent = 4
	}

	h := &Hasher{
		cfg: cfg,
		sem: make(chan struct{}, cfg.MaxConcurrent),
	}

	// Precompute dummy hash for constant-time email enumeration defense
	dummyHash, err := h.hashInternal("KeystoneDummyPassword123!")
	if err != nil {
		return nil, fmt.Errorf("failed to precompute dummy hash: %w", err)
	}
	h.dummyHash = dummyHash

	return h, nil
}

// ValidatePolicy checks password length (12..128), normalizes NFKC, and checks common lists.
func ValidatePolicy(rawPassword string) (string, error) {
	normalized := norm.NFKC.String(rawPassword)
	charCount := utf8.RuneCountInString(normalized)

	if charCount < 12 {
		return "", ErrPasswordTooShort
	}
	if charCount > 128 {
		return "", ErrPasswordTooLong
	}

	if _, breached := topBreachedPasswords[strings.ToLower(normalized)]; breached {
		return "", ErrPasswordBreached
	}

	return normalized, nil
}

// Hash hashes a plaintext password and returns a PHC-formatted string.
func (h *Hasher) Hash(rawPassword string) (string, error) {
	normalized, err := ValidatePolicy(rawPassword)
	if err != nil {
		return "", err
	}

	return h.hashWithThrottling(normalized)
}

func (h *Hasher) hashWithThrottling(password string) (string, error) {
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	default:
		return "", ErrBusy
	}

	return h.hashInternal(password)
}

func (h *Hasher) hashInternal(password string) (string, error) {
	salt := make([]byte, h.cfg.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate random salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, h.cfg.Iterations, h.cfg.MemoryKiB, h.cfg.Parallelism, h.cfg.KeyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=3,p=2$<b64salt>$<b64hash>
	phc := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.cfg.MemoryKiB, h.cfg.Iterations, h.cfg.Parallelism, b64Salt, b64Hash)

	return phc, nil
}

// Verify compares a candidate password against an Argon2id PHC string in constant time.
func (h *Hasher) Verify(candidatePassword, phcHash string) (bool, bool, error) {
	normalized := norm.NFKC.String(candidatePassword)

	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
	default:
		return false, false, ErrBusy
	}

	match, needsRehash, err := h.verifyInternal(normalized, phcHash)
	return match, needsRehash, err
}

// VerifyDummy runs constant-time verification against the precomputed dummy hash.
func (h *Hasher) VerifyDummy(candidatePassword string) {
	normalized := norm.NFKC.String(candidatePassword)
	select {
	case h.sem <- struct{}{}:
		defer func() { <-h.sem }()
		_, _, _ = h.verifyInternal(normalized, h.dummyHash)
	default:
		// Saturated; exit silently to bound timing
	}
}

func (h *Hasher) verifyInternal(password, phcHash string) (bool, bool, error) {
	// Expected parts: ["", "argon2id", "v=19", "m=65536,t=3,p=2", "<b64salt>", "<b64hash>"]
	parts := strings.Split(phcHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false, ErrInvalidHashFormat
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false, ErrInvalidHashFormat
	}

	var memory uint32
	var iterations uint32
	var parallelism uint32

	params := strings.Split(parts[3], ",")
	for _, p := range params {
		kv := strings.Split(p, "=")
		if len(kv) != 2 {
			continue
		}
		val, err := strconv.ParseUint(kv[1], 10, 32)
		if err != nil {
			return false, false, ErrInvalidHashFormat
		}
		switch kv[0] {
		case "m":
			memory = uint32(val)
		case "t":
			iterations = uint32(val)
		case "p":
			parallelism = uint32(val)
		}
	}

	if memory == 0 || iterations == 0 || parallelism == 0 || parallelism > 255 {
		return false, false, ErrInvalidHashFormat
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false, ErrInvalidHashFormat
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, false, ErrInvalidHashFormat
	}

	computedHash := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(parallelism), uint32(len(expectedHash)))

	match := subtle.ConstantTimeCompare(expectedHash, computedHash) == 1

	needsRehash := memory != h.cfg.MemoryKiB || iterations != h.cfg.Iterations || uint8(parallelism) != h.cfg.Parallelism

	return match, needsRehash, nil
}
