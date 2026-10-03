package token

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/raviteja-core/keystone/internal/auth/keys"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token is expired")
	ErrInvalidIssuer      = errors.New("invalid token issuer")
	ErrInvalidAudience    = errors.New("invalid token audience")
	ErrInvalidAlgorithm   = errors.New("unsupported algorithm: only RS256 is permitted")
	ErrInvalidTokenType   = errors.New("invalid token type: expected at+jwt")
	ErrSigningKeyNotFound = errors.New("signing key not found")
)

// AccessTokenParams holds parameters for issuing an RFC 9068 JWT access token.
type AccessTokenParams struct {
	Issuer    string
	Subject   string // user UUID or client_id
	Audiences []string
	ClientID  string
	Scope     string
	SessionID *string
	AMR       []string
	TTL       time.Duration
}

// IDTokenParams holds parameters for issuing an OIDC ID token.
type IDTokenParams struct {
	Issuer        string
	Subject       string
	ClientID      string // aud = client_id
	AuthTime      time.Time
	Nonce         *string
	AccessToken   string // used to compute at_hash
	SessionID     *string
	AMR           []string
	Scope         string
	Email         *string
	EmailVerified *bool
	Username      *string
	DisplayName   *string
	UpdatedAt     *time.Time
	TTL           time.Duration
}

// AccessTokenClaims represents RFC 9068 claims.
type AccessTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	Expiry    int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ID        string   `json:"jti"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope"`
	SessionID string   `json:"sid,omitempty"`
	AMR       []string `json:"amr,omitempty"`
}

// IDTokenClaims represents OIDC Core ID Token claims.
type IDTokenClaims struct {
	Issuer            string   `json:"iss"`
	Subject           string   `json:"sub"`
	Audience          string   `json:"aud"` // client_id
	Expiry            int64    `json:"exp"`
	IssuedAt          int64    `json:"iat"`
	AuthTime          int64    `json:"auth_time"`
	Nonce             string   `json:"nonce,omitempty"`
	AtHash            string   `json:"at_hash,omitempty"`
	SessionID         string   `json:"sid,omitempty"`
	AMR               []string `json:"amr,omitempty"`
	Email             string   `json:"email,omitempty"`
	EmailVerified     *bool    `json:"email_verified,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Name              string   `json:"name,omitempty"`
	UpdatedAt         int64    `json:"updated_at,omitempty"`
}

// Issuer issues and signs access and ID tokens.
type Issuer struct {
	key *keys.SigningKey
}

// NewIssuer creates a token Issuer.
func NewIssuer(key *keys.SigningKey) *Issuer {
	return &Issuer{key: key}
}

// IssueAccessToken creates an RS256 signed JWT with typ="at+jwt".
func (i *Issuer) IssueAccessToken(params AccessTokenParams) (string, error) {
	if i.key == nil || i.key.PrivateKey == nil {
		return "", ErrSigningKeyNotFound
	}

	sigKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       i.key.PrivateKey,
	}

	opts := (&jose.SignerOptions{}).
		WithType("at+jwt").
		WithHeader("kid", i.key.KID)

	signer, err := jose.NewSigner(sigKey, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	now := time.Now()
	jti, err := ids.NewUUIDv7()
	if err != nil {
		jti = uuid.New()
	}

	claims := AccessTokenClaims{
		Issuer:    params.Issuer,
		Subject:   params.Subject,
		Audience:  params.Audiences,
		Expiry:    now.Add(params.TTL).Unix(),
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ID:        jti.String(),
		ClientID:  params.ClientID,
		Scope:     params.Scope,
		AMR:       params.AMR,
	}
	if params.SessionID != nil {
		claims.SessionID = *params.SessionID
	}

	rawJWT, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return rawJWT, nil
}

// IssueIDToken creates an RS256 signed OIDC ID Token with typ="JWT".
func (i *Issuer) IssueIDToken(params IDTokenParams) (string, error) {
	if i.key == nil || i.key.PrivateKey == nil {
		return "", ErrSigningKeyNotFound
	}

	sigKey := jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       i.key.PrivateKey,
	}

	opts := (&jose.SignerOptions{}).
		WithType("JWT").
		WithHeader("kid", i.key.KID)

	signer, err := jose.NewSigner(sigKey, opts)
	if err != nil {
		return "", fmt.Errorf("failed to create signer: %w", err)
	}

	now := time.Now()
	claims := IDTokenClaims{
		Issuer:   params.Issuer,
		Subject:  params.Subject,
		Audience: params.ClientID,
		Expiry:   now.Add(params.TTL).Unix(),
		IssuedAt: now.Unix(),
		AuthTime: params.AuthTime.Unix(),
		AMR:      params.AMR,
	}

	if params.Nonce != nil {
		claims.Nonce = *params.Nonce
	}
	if params.SessionID != nil {
		claims.SessionID = *params.SessionID
	}

	// Compute at_hash if access token is provided: base64url(SHA256(access_token)[:16])
	if params.AccessToken != "" {
		claims.AtHash = ComputeAtHash(params.AccessToken)
	}

	// Add profile/email claims according to scope
	scopes := strings.Fields(params.Scope)
	hasEmailScope := false
	hasProfileScope := false
	for _, s := range scopes {
		if s == "email" {
			hasEmailScope = true
		} else if s == "profile" {
			hasProfileScope = true
		}
	}

	if hasEmailScope && params.Email != nil {
		claims.Email = *params.Email
		claims.EmailVerified = params.EmailVerified
	}
	if hasProfileScope {
		if params.Username != nil {
			claims.PreferredUsername = *params.Username
		}
		if params.DisplayName != nil {
			claims.Name = *params.DisplayName
		}
		if params.UpdatedAt != nil {
			claims.UpdatedAt = params.UpdatedAt.Unix()
		}
	}

	rawJWT, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return rawJWT, nil
}

// ComputeAtHash computes the OIDC at_hash for an RS256 access token.
func ComputeAtHash(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:16])
}
