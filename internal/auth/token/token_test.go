package token_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/raviteja-core/keystone/internal/auth/keys"
	"github.com/raviteja-core/keystone/internal/auth/token"
)

func setupTestKey(t *testing.T) (*keys.SigningKey, *token.Issuer) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	rawJWK := jose.JSONWebKey{
		Key:       &priv.PublicKey,
		Algorithm: "RS256",
		Use:       "sig",
	}
	tb, err := rawJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("failed to compute thumbprint: %v", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(tb)
	rawJWK.KeyID = kid

	k := &keys.SigningKey{
		KID:        kid,
		Algorithm:  "RS256",
		Status:     "active",
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		PublicJWK:  rawJWK,
		CreatedAt:  time.Now(),
	}

	return k, token.NewIssuer(k)
}

func TestToken_IssueAndValidateAccessToken(t *testing.T) {
	key, issuer := setupTestKey(t)

	sessID := "session-12345"
	params := token.AccessTokenParams{
		Issuer:    "http://localhost:8080",
		Subject:   "usr-789",
		Audiences: []string{"https://api.example.com"},
		ClientID:  "test-client",
		Scope:     "openid profile email",
		SessionID: &sessID,
		AMR:       []string{"pwd"},
		TTL:       10 * time.Minute,
	}

	at, err := issuer.IssueAccessToken(params)
	if err != nil {
		t.Fatalf("failed to issue access token: %v", err)
	}

	if at == "" {
		t.Fatal("expected non-empty access token")
	}

	// Independent validation
	validator := token.NewValidator("http://localhost:8080", "https://api.example.com", func(kid string) (*rsa.PublicKey, error) {
		if kid != key.KID {
			return nil, token.ErrSigningKeyNotFound
		}
		return key.PublicKey, nil
	})

	claims, err := validator.ValidateAccessToken(at)
	if err != nil {
		t.Fatalf("expected access token to validate successfully, got: %v", err)
	}

	if claims.Subject != "usr-789" {
		t.Errorf("expected sub usr-789, got %q", claims.Subject)
	}
	if claims.ClientID != "test-client" {
		t.Errorf("expected client_id test-client, got %q", claims.ClientID)
	}
	if claims.SessionID != sessID {
		t.Errorf("expected sid %q, got %q", sessID, claims.SessionID)
	}
	if claims.Scope != "openid profile email" {
		t.Errorf("expected scope 'openid profile email', got %q", claims.Scope)
	}
}

func TestToken_IDTokenRejectedAsAccessToken(t *testing.T) {
	key, issuer := setupTestKey(t)

	nonce := "random-nonce-123"
	email := "alice@example.com"
	verified := true
	idToken, err := issuer.IssueIDToken(token.IDTokenParams{
		Issuer:        "http://localhost:8080",
		Subject:       "usr-789",
		ClientID:      "test-client",
		AuthTime:      time.Now(),
		Nonce:         &nonce,
		AccessToken:   "some-access-token",
		Scope:         "openid email",
		Email:         &email,
		EmailVerified: &verified,
		TTL:           10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to issue ID token: %v", err)
	}

	validator := token.NewValidator("http://localhost:8080", "test-client", func(kid string) (*rsa.PublicKey, error) {
		return key.PublicKey, nil
	})

	// Validating ID token as access token MUST fail because typ != at+jwt
	_, err = validator.ValidateAccessToken(idToken)
	if err == nil {
		t.Fatal("expected ID token to be rejected by access token validator, but got success")
	}
	if !strings.Contains(err.Error(), "expected at+jwt") {
		t.Errorf("expected error mentioning at+jwt, got: %v", err)
	}
}

func TestToken_ValidationRejections(t *testing.T) {
	key, issuer := setupTestKey(t)

	params := token.AccessTokenParams{
		Issuer:    "http://localhost:8080",
		Subject:   "usr-1",
		Audiences: []string{"https://api.example.com"},
		ClientID:  "client-1",
		Scope:     "openid",
		TTL:       50 * time.Millisecond,
	}

	at, err := issuer.IssueAccessToken(params)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	// 1. Wrong issuer
	wrongIssValidator := token.NewValidator("http://wrong-issuer.com", "https://api.example.com", func(kid string) (*rsa.PublicKey, error) {
		return key.PublicKey, nil
	})
	if _, err := wrongIssValidator.ValidateAccessToken(at); err == nil {
		t.Error("expected wrong issuer to fail validation")
	}

	// 2. Wrong audience
	wrongAudValidator := token.NewValidator("http://localhost:8080", "https://other-api.com", func(kid string) (*rsa.PublicKey, error) {
		return key.PublicKey, nil
	})
	if _, err := wrongAudValidator.ValidateAccessToken(at); err == nil {
		t.Error("expected wrong audience to fail validation")
	}

	// 3. Unknown kid
	unknownKidValidator := token.NewValidator("http://localhost:8080", "https://api.example.com", func(kid string) (*rsa.PublicKey, error) {
		return nil, token.ErrSigningKeyNotFound
	})
	if _, err := unknownKidValidator.ValidateAccessToken(at); err == nil {
		t.Error("expected unknown kid to fail validation")
	}

	// 4. Expired token
	expiredParams := params
	expiredParams.TTL = -5 * time.Minute
	expiredToken, _ := issuer.IssueAccessToken(expiredParams)
	validValidator := token.NewValidator("http://localhost:8080", "https://api.example.com", func(kid string) (*rsa.PublicKey, error) {
		return key.PublicKey, nil
	})
	if _, err := validValidator.ValidateAccessToken(expiredToken); err != token.ErrTokenExpired {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

func TestToken_ComputeAtHash(t *testing.T) {
	// RFC 7636 / OIDC Core:
	// Verify that at_hash is 16 bytes base64url encoded (length 22)
	at := "jHkWEdUXweAlq-ASxbocqWj0"
	atHash := token.ComputeAtHash(at)
	if len(atHash) != 22 {
		t.Errorf("expected at_hash length 22, got %d (%q)", len(atHash), atHash)
	}
}
