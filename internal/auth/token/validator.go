package token

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Validator validates incoming JWT access tokens.
type Validator struct {
	expectedIssuer string
	expectedAud    string
	keyProvider    func(kid string) (*rsa.PublicKey, error)
	leeway         time.Duration
}

// NewValidator creates a token Validator.
func NewValidator(expectedIssuer, expectedAud string, keyProvider func(kid string) (*rsa.PublicKey, error)) *Validator {
	return &Validator{
		expectedIssuer: expectedIssuer,
		expectedAud:    expectedAud,
		keyProvider:    keyProvider,
		leeway:         30 * time.Second,
	}
}

// ValidateAccessToken parses and validates an RFC 9068 access token.
func (v *Validator) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	// Parse without verifying first to inspect header
	tok, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse JWT (algorithm must be RS256): %v", ErrInvalidToken, err)
	}

	if len(tok.Headers) == 0 {
		return nil, fmt.Errorf("%w: missing JOSE header", ErrInvalidToken)
	}

	hdr := tok.Headers[0]

	// 1. Enforce RS256 algorithm allowlist strictly
	if hdr.Algorithm != string(jose.RS256) {
		return nil, ErrInvalidAlgorithm
	}

	// 2. Enforce typ == at+jwt (case-insensitive per RFC 9068)
	typHeader, ok := hdr.ExtraHeaders["typ"].(string)
	if !ok || !strings.EqualFold(typHeader, "at+jwt") {
		return nil, fmt.Errorf("%w: got typ=%q, expected at+jwt", ErrInvalidTokenType, typHeader)
	}

	// 3. Look up key by kid
	pubKey, err := v.keyProvider(hdr.KeyID)
	if err != nil || pubKey == nil {
		return nil, fmt.Errorf("%w: unknown kid %q", ErrSigningKeyNotFound, hdr.KeyID)
	}

	// 4. Verify signature and deserialize claims
	var claims AccessTokenClaims
	if err := tok.Claims(pubKey, &claims); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidToken, err)
	}

	now := time.Now()

	// 5. Enforce issuer exact match
	if claims.Issuer != v.expectedIssuer {
		return nil, fmt.Errorf("%w: got %q, expected %q", ErrInvalidIssuer, claims.Issuer, v.expectedIssuer)
	}

	// 6. Enforce audience
	if v.expectedAud != "" {
		audMatched := false
		for _, aud := range claims.Audience {
			if aud == v.expectedAud {
				audMatched = true
				break
			}
		}
		if !audMatched {
			return nil, fmt.Errorf("%w: token audiences %v do not include %q", ErrInvalidAudience, claims.Audience, v.expectedAud)
		}
	}

	// 7. Enforce expiration with leeway
	expTime := time.Unix(claims.Expiry, 0)
	if now.After(expTime.Add(v.leeway)) {
		return nil, ErrTokenExpired
	}

	// Enforce nbf with leeway
	if claims.NotBefore > 0 {
		nbfTime := time.Unix(claims.NotBefore, 0)
		if now.Before(nbfTime.Add(-v.leeway)) {
			return nil, errors.New("token is not yet valid")
		}
	}

	return &claims, nil
}
