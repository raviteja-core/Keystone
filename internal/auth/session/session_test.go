package session_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/auth/session"
	"github.com/raviteja-core/keystone/internal/auth/store"
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
		t.Skipf("skipping session test: PostgreSQL not available: %v", err)
	}

	return pool
}

func TestSession_CookieSecurityFlags(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)

	// Test 1: Prod mode with Secure=true
	mgrProd := session.NewManager(s, session.Config{
		CookieSecure: true,
		IdleTTL:      30 * time.Minute,
		AbsoluteTTL:  12 * time.Hour,
	})

	if mgrProd.SessionCookieName() != "__Host-keystone_session" {
		t.Errorf("expected __Host- prefix in secure mode, got %q", mgrProd.SessionCookieName())
	}
	if mgrProd.CSRFCookieName() != "__Host-keystone_csrf" {
		t.Errorf("expected __Host- prefix in secure mode for CSRF, got %q", mgrProd.CSRFCookieName())
	}

	w := httptest.NewRecorder()
	mgrProd.SetSessionCookie(w, "test-session-id")

	cookie := w.Result().Cookies()[0]
	if !cookie.HttpOnly {
		t.Error("expected HttpOnly=true")
	}
	if !cookie.Secure {
		t.Error("expected Secure=true")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite=Lax, got %v", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Errorf("expected Path=/, got %q", cookie.Path)
	}
}

func TestSession_FixationDefense(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	u := &store.User{
		ID:           uid,
		Email:        "sess_test_" + uid.String() + "@example.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$test$test",
	}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	mgr := session.NewManager(s, session.Config{
		CookieSecure: false,
		IdleTTL:      30 * time.Minute,
		AbsoluteTTL:  12 * time.Hour,
	})

	// Pre-login session
	req := httptest.NewRequest("GET", "http://localhost:8080/login", nil)
	w1 := httptest.NewRecorder()
	oldSessionID, oldSess, err := mgr.CreateSession(w1, req, uid, []string{"pwd"})
	if err != nil {
		t.Fatalf("failed to create initial session: %v", err)
	}

	// Login succeeds: regenerate session
	w2 := httptest.NewRecorder()
	newSessionID, newSess, err := mgr.RegenerateSession(w2, req, oldSessionID, uid, []string{"pwd"})
	if err != nil {
		t.Fatalf("failed to regenerate session: %v", err)
	}

	// Session ID must change!
	if newSessionID == oldSessionID {
		t.Fatal("expected session ID to change upon login regeneration")
	}

	// Old session must now be revoked
	oldHash := ids.SHA256Digest([]byte(oldSessionID))
	revokedSess, err := s.GetSessionByHash(ctx, oldHash)
	if err != nil {
		t.Fatalf("failed to query old session: %v", err)
	}
	if revokedSess.RevokedAt == nil {
		t.Error("expected old session to have non-nil RevokedAt")
	}

	// New session must be active
	reqAfterLogin := httptest.NewRequest("GET", "http://localhost:8080/dashboard", nil)
	reqAfterLogin.AddCookie(&http.Cookie{
		Name:  mgr.SessionCookieName(),
		Value: newSessionID,
	})
	activeSess, err := mgr.GetSession(reqAfterLogin)
	if err != nil {
		t.Fatalf("expected new session to be active, got: %v", err)
	}
	if activeSess.UserID != uid {
		t.Errorf("expected user id %v, got %v", uid, activeSess.UserID)
	}
	_ = oldSess
	_ = newSess
}

func TestSession_CSRFValidation(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)

	mgr := session.NewManager(s, session.Config{
		CookieSecure: false,
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/login", nil)

	csrfToken, err := mgr.EnsureCSRFToken(w, r)
	if err != nil {
		t.Fatalf("failed to issue CSRF token: %v", err)
	}

	if len(csrfToken) < 32 {
		t.Fatalf("expected CSRF token length >= 32, got %d", len(csrfToken))
	}

	// Case 1: Matching form token
	postReq := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{
		"csrf_token": {csrfToken},
	}.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(&http.Cookie{
		Name:  mgr.CSRFCookieName(),
		Value: csrfToken,
	})

	if err := mgr.ValidateCSRF(postReq); err != nil {
		t.Errorf("expected valid CSRF token to pass, got: %v", err)
	}

	// Case 2: Matching header token
	postHeaderReq := httptest.NewRequest("POST", "/login", nil)
	postHeaderReq.Header.Set("X-CSRF-Token", csrfToken)
	postHeaderReq.AddCookie(&http.Cookie{
		Name:  mgr.CSRFCookieName(),
		Value: csrfToken,
	})
	if err := mgr.ValidateCSRF(postHeaderReq); err != nil {
		t.Errorf("expected valid CSRF header to pass, got: %v", err)
	}

	// Case 3: Missing CSRF token
	noTokenReq := httptest.NewRequest("POST", "/login", nil)
	noTokenReq.AddCookie(&http.Cookie{
		Name:  mgr.CSRFCookieName(),
		Value: csrfToken,
	})
	if err := mgr.ValidateCSRF(noTokenReq); err != session.ErrInvalidCSRF {
		t.Errorf("expected ErrInvalidCSRF on missing token, got: %v", err)
	}

	// Case 4: Wrong CSRF token
	wrongTokenReq := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{
		"csrf_token": {"wrong-token-value"},
	}.Encode()))
	wrongTokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongTokenReq.AddCookie(&http.Cookie{
		Name:  mgr.CSRFCookieName(),
		Value: csrfToken,
	})
	if err := mgr.ValidateCSRF(wrongTokenReq); err != session.ErrInvalidCSRF {
		t.Errorf("expected ErrInvalidCSRF on mismatched token, got: %v", err)
	}
}
