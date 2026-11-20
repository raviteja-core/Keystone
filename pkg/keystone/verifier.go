package keystone

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Verifier validates incoming RFC 9068 JWT access tokens.
type Verifier struct {
	expectedIssuer string
	expectedAud    string
	clockSkew      time.Duration
	keyProvider    KeyProvider
	jwksCache      *JWKSCache
}

// VerifierOption configures a Verifier instance.
type VerifierOption func(*verifierConfig)

type verifierConfig struct {
	jwksURL            string
	httpClient         *httpDoer
	clockSkew          time.Duration
	keyProvider        KeyProvider
	jwksTTL            time.Duration
	minRefetchInterval time.Duration
}

type httpDoer = func() // placeholder or use *http.Client

// WithJWKSURL sets a custom JWKS URL.
func WithJWKSURL(url string) VerifierOption {
	return func(c *verifierConfig) {
		c.jwksURL = url
	}
}

// WithClockSkew configures the allowed clock skew leeway (default: 30 seconds).
func WithClockSkew(d time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		c.clockSkew = d
	}
}

// WithKeyProvider sets a custom key provider function (e.g. for testing).
func WithKeyProvider(kp KeyProvider) VerifierOption {
	return func(c *verifierConfig) {
		c.keyProvider = kp
	}
}

// WithJWKSCacheTTL configures the TTL for cached JWKS keys.
func WithJWKSCacheTTL(ttl time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		c.jwksTTL = ttl
	}
}

// WithMinRefetchInterval configures the rate-limiting minimum interval between refetches for unknown kids.
func WithMinRefetchInterval(interval time.Duration) VerifierOption {
	return func(c *verifierConfig) {
		c.minRefetchInterval = interval
	}
}

// NewVerifier creates a new token Verifier for the specified issuer and audience.
func NewVerifier(expectedIssuer, expectedAud string, opts ...VerifierOption) (*Verifier, error) {
	if expectedIssuer == "" {
		return nil, fmt.Errorf("expectedIssuer must not be empty")
	}

	cfg := &verifierConfig{
		clockSkew:          30 * time.Second,
		jwksTTL:            1 * time.Hour,
		minRefetchInterval: 10 * time.Second,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	v := &Verifier{
		expectedIssuer: strings.TrimRight(expectedIssuer, "/"),
		expectedAud:    expectedAud,
		clockSkew:      cfg.clockSkew,
		keyProvider:    cfg.keyProvider,
	}

	if v.keyProvider == nil {
		jwksURL := cfg.jwksURL
		if jwksURL == "" {
			jwksURL = v.expectedIssuer + "/jwks.json"
		}
		v.jwksCache = NewJWKSCache(jwksURL, nil, cfg.jwksTTL, cfg.minRefetchInterval)
		v.keyProvider = v.jwksCache.GetKey
	}

	return v, nil
}

// rawClaims is an internal representation used for RFC 9068 deserialization.
type rawClaims struct {
	Issuer    string      `json:"iss"`
	Subject   string      `json:"sub"`
	Audience  interface{} `json:"aud"`
	ClientID  string      `json:"client_id"`
	Scope     string      `json:"scope"`
	JTI       string      `json:"jti"`
	Expiry    int64       `json:"exp"`
	NotBefore int64       `json:"nbf,omitempty"`
	IssuedAt  int64       `json:"iat"`
}

// Verify parses and verifies an RFC 9068 JWT access token string.
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*Claims, error) {
	// Parse with strict signature algorithm allowlist: only RS256
	tok, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse JWT (algorithm must be RS256): %v", ErrInvalidToken, err)
	}

	if len(tok.Headers) == 0 {
		return nil, ErrMissingJOSEHeader
	}

	hdr := tok.Headers[0]

	// 1. Strict algorithm allowlist check (rejects "none", "HS256", etc.)
	if hdr.Algorithm != string(jose.RS256) {
		return nil, ErrInvalidAlgorithm
	}

	// 2. Enforce typ == at+jwt (case-insensitive per RFC 9068)
	typHeader, ok := hdr.ExtraHeaders["typ"].(string)
	if !ok || !strings.EqualFold(typHeader, "at+jwt") {
		return nil, fmt.Errorf("%w: got typ=%q, expected at+jwt", ErrInvalidTokenType, typHeader)
	}

	// 3. Obtain public key using KeyID (kid)
	if hdr.KeyID == "" {
		return nil, ErrMissingKeyID
	}

	pubKey, err := v.keyProvider(ctx, hdr.KeyID)
	if err != nil || pubKey == nil {
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", ErrSigningKeyNotFound, hdr.KeyID)
	}

	// 4. Verify cryptographic signature and deserialize claims
	var raw rawClaims
	if err := tok.Claims(pubKey, &raw); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidToken, err)
	}

	now := time.Now()

	// 5. Enforce issuer exact match
	if strings.TrimRight(raw.Issuer, "/") != v.expectedIssuer {
		return nil, fmt.Errorf("%w: got %q, expected %q", ErrInvalidIssuer, raw.Issuer, v.expectedIssuer)
	}

	// 6. Normalize and enforce audience
	audiences := parseAudiences(raw.Audience)
	if v.expectedAud != "" {
		matched := false
		for _, a := range audiences {
			if a == v.expectedAud {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("%w: audiences %v do not match expected %q", ErrInvalidAudience, audiences, v.expectedAud)
		}
	}

	// 7. Enforce expiration with clock skew leeway
	if raw.Expiry > 0 {
		expTime := time.Unix(raw.Expiry, 0)
		if now.After(expTime.Add(v.clockSkew)) {
			return nil, ErrTokenExpired
		}
	} else {
		return nil, fmt.Errorf("%w: missing exp claim", ErrInvalidToken)
	}

	// 8. Enforce not before (nbf) with clock skew leeway
	var nbfTime *time.Time
	if raw.NotBefore > 0 {
		t := time.Unix(raw.NotBefore, 0)
		nbfTime = &t
		if now.Before(t.Add(-v.clockSkew)) {
			return nil, ErrTokenNotYetValid
		}
	}

	claims := &Claims{
		Subject:   raw.Subject,
		Issuer:    raw.Issuer,
		Audiences: audiences,
		ClientID:  raw.ClientID,
		Scope:     raw.Scope,
		JTI:       raw.JTI,
		IssuedAt:  time.Unix(raw.IssuedAt, 0),
		ExpiresAt: time.Unix(raw.Expiry, 0),
		NotBefore: nbfTime,
	}

	return claims, nil
}

func parseAudiences(raw interface{}) []string {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []interface{}:
		var res []string
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				res = append(res, s)
			}
		}
		return res
	case []string:
		return v
	default:
		return nil
	}
}
