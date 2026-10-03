package userinfo_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/auth/keys"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/auth/token"
	"github.com/raviteja-core/keystone/internal/auth/userinfo"
	"github.com/raviteja-core/keystone/internal/platform/db"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

func getTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("KEYSTONE_DB_URL")
	if dbURL == "" {
		port := os.Getenv("KEYSTONE_POSTGRES_PORT")
		if port == "" {
			port = "54320"
		}
		dbURL = "postgres://keystone_auth_app:auth_dev_password@localhost:" + port + "/keystone_auth?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pool, err := db.NewPool(ctx, db.DefaultConfig(dbURL))
	if err != nil {
		t.Skipf("skipping userinfo test: PostgreSQL not available: %v", err)
	}

	return pool
}

func setupUserInfoTest(t *testing.T) (*userinfo.Handler, *token.Issuer, *store.Store, *store.User) {
	t.Helper()
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	rawJWK := jose.JSONWebKey{
		Key:       &priv.PublicKey,
		Algorithm: "RS256",
		Use:       "sig",
	}
	tb, _ := rawJWK.Thumbprint(crypto.SHA256)
	kid := base64.RawURLEncoding.EncodeToString(tb)
	rawJWK.KeyID = kid

	k := &keys.SigningKey{
		KID:        kid,
		Algorithm:  "RS256",
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		PublicJWK:  rawJWK,
	}

	issuer := token.NewIssuer(k)

	validator := token.NewValidator("http://localhost:8080", "", func(askedKid string) (*rsa.PublicKey, error) {
		if askedKid != kid {
			return nil, token.ErrSigningKeyNotFound
		}
		return &priv.PublicKey, nil
	})

	handler := userinfo.NewHandler(validator, s)

	// Create user
	uid, _ := ids.NewUUIDv7()
	uname := "bob_" + strings.ReplaceAll(uid.String(), "-", "")
	dname := "Bob Test"
	u := &store.User{
		ID:            uid,
		Email:         "bob_" + uid.String() + "@example.com",
		Username:      &uname,
		DisplayName:   &dname,
		PasswordHash:  "hash",
		EmailVerified: true,
	}
	_ = s.CreateUser(ctx, u)

	return handler, issuer, s, u
}

func TestUserInfo_HappyPath(t *testing.T) {
	handler, issuer, _, user := setupUserInfoTest(t)

	// Issue access token with openid profile email
	at, err := issuer.IssueAccessToken(token.AccessTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  user.ID.String(),
		ClientID: "test-client",
		Scope:    "openid profile email",
		TTL:      10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to issue access token: %v", err)
	}

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from /userinfo, got %d", resp.StatusCode)
	}

	var res userinfo.UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode userinfo response: %v", err)
	}

	if res.Subject != user.ID.String() {
		t.Errorf("expected sub %s, got %s", user.ID.String(), res.Subject)
	}
	if res.Email != user.Email {
		t.Errorf("expected email %s, got %s", user.Email, res.Email)
	}
	if res.Name != *user.DisplayName {
		t.Errorf("expected name %s, got %s", *user.DisplayName, res.Name)
	}
	if res.PreferredUsername != *user.Username {
		t.Errorf("expected preferred_username %s, got %s", *user.Username, res.PreferredUsername)
	}
}

func TestUserInfo_ScopeAndTokenTypeEnforcement(t *testing.T) {
	handler, issuer, _, user := setupUserInfoTest(t)

	// AS-35: Scope missing 'openid' -> 403 Forbidden
	tokenNoOpenID, _ := issuer.IssueAccessToken(token.AccessTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  user.ID.String(),
		ClientID: "test-client",
		Scope:    "profile email", // openid is missing!
		TTL:      10 * time.Minute,
	})

	reqNoOpenID := httptest.NewRequest("GET", "/userinfo", nil)
	reqNoOpenID.Header.Set("Authorization", "Bearer "+tokenNoOpenID)
	wNoOpenID := httptest.NewRecorder()

	handler.ServeHTTP(wNoOpenID, reqNoOpenID)
	if wNoOpenID.Result().StatusCode != http.StatusForbidden {
		t.Errorf("AS-35: expected 403 Forbidden when openid scope missing, got %d", wNoOpenID.Result().StatusCode)
	}

	// AS-36: ID token presented as Bearer token -> rejected with 401 Unauthorized
	idToken, _ := issuer.IssueIDToken(token.IDTokenParams{
		Issuer:   "http://localhost:8080",
		Subject:  user.ID.String(),
		ClientID: "test-client",
		AuthTime: time.Now(),
		Scope:    "openid",
		TTL:      10 * time.Minute,
	})

	reqIDTok := httptest.NewRequest("GET", "/userinfo", nil)
	reqIDTok.Header.Set("Authorization", "Bearer "+idToken)
	wIDTok := httptest.NewRecorder()

	handler.ServeHTTP(wIDTok, reqIDTok)
	if wIDTok.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("AS-36: expected 401 Unauthorized when ID token presented as Bearer on /userinfo, got %d", wIDTok.Result().StatusCode)
	}
}
