package ids

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
)

// NewUUIDv7 generates an RFC 9562 UUIDv7.
func NewUUIDv7() (uuid.UUID, error) {
	return uuid.NewV7()
}

// RandomBase64URL generates n random bytes from crypto/rand and returns standard unpadded base64url string.
func RandomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SHA256Digest computes SHA-256 digest of input and returns byte slice.
func SHA256Digest(input []byte) []byte {
	h := sha256.Sum256(input)
	return h[:]
}

// SHA256DigestString computes SHA-256 digest of a string input and returns byte slice.
func SHA256DigestString(input string) []byte {
	return SHA256Digest([]byte(input))
}

// ConstantTimeCompare compares two byte slices in constant time.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeStringCompare compares two strings in constant time.
func ConstantTimeStringCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
