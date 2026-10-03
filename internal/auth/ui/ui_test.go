package ui_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/auth/audit"
	"github.com/raviteja-core/keystone/internal/auth/password"
	"github.com/raviteja-core/keystone/internal/auth/session"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/auth/ui"
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
		t.Skipf("skipping UI integration test: PostgreSQL not available: %v", err)
	}

	return pool
}

func setupUIHandler(t *testing.T) (*ui.Handler, *session.Manager, *store.Store) {
	t.Helper()
	pool := getTestPool(t)
	s := store.New(pool)
	sm := session.NewManager(s, session.Config{CookieSecure: false})
	hasher, err := password.NewHasher(password.Config{
		MemoryKiB:     65536,
		Iterations:    3,
		Parallelism:   2,
		MaxConcurrent: 4,
	})
	if err != nil {
		t.Fatalf("failed to create hasher: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	aw := audit.NewWriter(pool)
	handler := ui.NewHandler(s, sm, hasher, aw, logger)
	return handler, sm, s
}

func TestUI_OpenRedirectDefense(t *testing.T) {
	attacks := []string{
		"https://evil.example",
		"//evil.example",
		"/\\evil.example",
		"/authorize@evil.example",
		"javascript:alert(1)",
		"http://evil.com/authorize",
		"/dashboard",
		"   /authorize",
	}

	for _, attack := range attacks {
		clean := ui.ValidateReturnTo(attack)
		if clean != "/" {
			t.Errorf("expected open redirect attack %q to be sanitized to /, got %q", attack, clean)
		}
	}

	// Valid authorize relative paths must be accepted
	valid := []string{
		"/authorize?client_id=foo&redirect_uri=bar",
		"/authorize",
	}
	for _, v := range valid {
		clean := ui.ValidateReturnTo(v)
		if clean != v {
			t.Errorf("expected valid return_to %q to be preserved, got %q", v, clean)
		}
	}
}

func TestUI_SecurityHeadersAndNoInlineScripts(t *testing.T) {
	handler, _, _ := setupUIHandler(t)

	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()

	handler.HandleLogin(w, req)
	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	// CSP header
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("missing required directives in CSP: %q", csp)
	}

	// X-Content-Type-Options
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got %q", resp.Header.Get("X-Content-Type-Options"))
	}

	// Cache-Control
	if !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		t.Errorf("expected Cache-Control: no-store, got %q", resp.Header.Get("Cache-Control"))
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	// No inline script tags
	if strings.Contains(bodyStr, "<script") {
		t.Error("HTML page MUST NOT contain <script> tags")
	}
	// No CDN assets (http:// or https:// outside self)
	if strings.Contains(bodyStr, "http://") || strings.Contains(bodyStr, "https://") {
		t.Error("HTML page MUST NOT load external CDN assets")
	}
}

func TestUI_CSRFEnforcement(t *testing.T) {
	handler, sm, _ := setupUIHandler(t)

	// POST /login without CSRF -> 403 Forbidden
	req := httptest.NewRequest("POST", "/login", strings.NewReader("email=a@example.com&password=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	handler.HandleLogin(w, req)
	if w.Result().StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden on missing CSRF token, got %d", w.Result().StatusCode)
	}

	// POST /register without CSRF -> 403 Forbidden
	reqReg := httptest.NewRequest("POST", "/register", strings.NewReader("email=a@example.com&password=secret"))
	reqReg.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wReg := httptest.NewRecorder()

	handler.HandleRegister(wReg, reqReg)
	if wReg.Result().StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden on missing CSRF token, got %d", wReg.Result().StatusCode)
	}

	_ = sm
}

func TestUI_UserEnumerationIndistinguishability(t *testing.T) {
	handler, sm, s := setupUIHandler(t)
	ctx := context.Background()

	// Create real user
	uid, _ := ids.NewUUIDv7()
	realEmail := "enum_test_" + uid.String() + "@example.com"
	hasher, _ := password.NewHasher(password.Config{
		MemoryKiB:     65536,
		Iterations:    3,
		Parallelism:   2,
		MaxConcurrent: 4,
	})
	hash, _ := hasher.Hash("CorrectPassword123!")

	_ = s.CreateUser(ctx, &store.User{
		ID:           uid,
		Email:        realEmail,
		PasswordHash: hash,
	})

	// Setup CSRF
	csrfToken, _ := ids.RandomBase64URL(32)

	// Attempt 1: Existing user with WRONG password
	form1 := url.Values{
		"csrf_token": {csrfToken},
		"email":      {realEmail},
		"password":   {"WrongPassword123!"},
	}
	req1 := httptest.NewRequest("POST", "/login", strings.NewReader(form1.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.AddCookie(&http.Cookie{Name: sm.CSRFCookieName(), Value: csrfToken})
	w1 := httptest.NewRecorder()

	handler.HandleLogin(w1, req1)
	resp1 := w1.Result()

	// Attempt 2: Non-existent user
	form2 := url.Values{
		"csrf_token": {csrfToken},
		"email":      {"nonexistent_user_99999@example.com"},
		"password":   {"WrongPassword123!"},
	}
	req2 := httptest.NewRequest("POST", "/login", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: sm.CSRFCookieName(), Value: csrfToken})
	w2 := httptest.NewRecorder()

	handler.HandleLogin(w2, req2)
	resp2 := w2.Result()

	// HTTP Status must be identical
	if resp1.StatusCode != resp2.StatusCode {
		t.Errorf("status mismatch: real user got %d, unknown user got %d", resp1.StatusCode, resp2.StatusCode)
	}

	body1, _ := io.ReadAll(resp1.Body)
	body2, _ := io.ReadAll(resp2.Body)

	// Body content must be identical
	if string(body1) != string(body2) {
		t.Errorf("response body reveals user existence: %q vs %q", string(body1), string(body2))
	}
}

func TestUI_RegisterHappyPathAndValidation(t *testing.T) {
	handler, sm, _ := setupUIHandler(t)

	csrfToken, _ := ids.RandomBase64URL(32)
	uid, _ := ids.NewUUIDv7()
	email := "reg_test_" + uid.String() + "@example.com"

	// Case 1: Short password < 12 characters -> rejected with 400
	shortForm := url.Values{
		"csrf_token": {csrfToken},
		"email":      {email},
		"password":   {"Short1!"},
	}
	reqShort := httptest.NewRequest("POST", "/register", strings.NewReader(shortForm.Encode()))
	reqShort.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqShort.AddCookie(&http.Cookie{Name: sm.CSRFCookieName(), Value: csrfToken})
	wShort := httptest.NewRecorder()

	handler.HandleRegister(wShort, reqShort)
	if wShort.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on password < 12 chars, got %d", wShort.Result().StatusCode)
	}

	// Case 2: Happy path registration -> creates account, sets session cookie, redirects 302
	validForm := url.Values{
		"csrf_token": {csrfToken},
		"email":      {email},
		"username":   {"alice_" + uid.String()},
		"password":   {"ValidSecurePassword123!"},
		"return_to":  {"/authorize?client_id=myclient"},
	}
	reqValid := httptest.NewRequest("POST", "/register", strings.NewReader(validForm.Encode()))
	reqValid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqValid.AddCookie(&http.Cookie{Name: sm.CSRFCookieName(), Value: csrfToken})
	wValid := httptest.NewRecorder()

	handler.HandleRegister(wValid, reqValid)
	respValid := wValid.Result()

	if respValid.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect after successful registration, got %d", respValid.StatusCode)
	}

	if respValid.Header.Get("Location") != "/authorize?client_id=myclient" {
		t.Errorf("expected redirect to return_to, got %q", respValid.Header.Get("Location"))
	}

	// Session cookie must be set
	cookies := respValid.Cookies()
	var sessCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == sm.SessionCookieName() {
			sessCookie = c
			break
		}
	}
	if sessCookie == nil || sessCookie.Value == "" {
		t.Fatal("expected session cookie to be set after registration")
	}
}

func TestUI_ConsentFlow(t *testing.T) {
	handler, sm, s := setupUIHandler(t)
	ctx := context.Background()

	// 1. Create a client
	cid, _ := ids.NewUUIDv7()
	client := &store.Client{
		ID:                      cid,
		ClientID:                "consent_client_" + strings.ReplaceAll(cid.String(), "-", ""),
		Name:                    "Consent Test App",
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
		RedirectURIs:            []string{"https://app.example.com/callback"},
		AllowedGrantTypes:       []string{"authorization_code"},
		AllowedScopes:           []string{"openid", "profile", "email"},
		RequireConsent:          true,
	}
	if err := s.CreateClient(ctx, client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// 2. GET /consent without session -> 302 to /login
	reqNoSess := httptest.NewRequest("GET", "/consent?client_id="+client.ClientID+"&scope=openid", nil)
	wNoSess := httptest.NewRecorder()
	handler.HandleConsent(wNoSess, reqNoSess)
	if wNoSess.Result().StatusCode != http.StatusFound || !strings.Contains(wNoSess.Result().Header.Get("Location"), "/login") {
		t.Fatalf("expected redirect to login when unauthenticated, got %d loc: %q",
			wNoSess.Result().StatusCode, wNoSess.Result().Header.Get("Location"))
	}

	// 3. Create user and active session
	uid, _ := ids.NewUUIDv7()
	user := &store.User{
		ID:           uid,
		Email:        "consent_user_" + strings.ReplaceAll(uid.String(), "-", "") + "@example.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$test$test",
	}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	wSess := httptest.NewRecorder()
	reqSess := httptest.NewRequest("GET", "/", nil)
	sessID, _, err := sm.CreateSession(wSess, reqSess, user.ID, []string{"pwd"})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	// 4. GET /consent with session -> 200 OK with client name and scope descriptions
	reqWithSess := httptest.NewRequest("GET", "/consent?client_id="+client.ClientID+"&scope=openid+profile&return_to=/authorize%3Fclient_id%3D"+client.ClientID, nil)
	reqWithSess.AddCookie(&http.Cookie{Name: sm.SessionCookieName(), Value: sessID})
	wWithSess := httptest.NewRecorder()
	handler.HandleConsent(wWithSess, reqWithSess)

	if wWithSess.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for consent GET, got %d", wWithSess.Result().StatusCode)
	}
	body := wWithSess.Body.String()
	if !strings.Contains(body, "Consent Test App") || !strings.Contains(body, "Verify your identity") {
		t.Fatalf("expected consent screen to render client name and scope details, got: %s", body)
	}

	// 5. POST /consent action=deny -> redirects to client redirect_uri with error=access_denied
	csrfToken, _ := sm.EnsureCSRFToken(httptest.NewRecorder(), reqWithSess)
	denyForm := url.Values{
		"csrf_token": {csrfToken},
		"client_id":  {client.ClientID},
		"scope":      {"openid profile"},
		"return_to":  {"/authorize?client_id=" + client.ClientID + "&redirect_uri=" + url.QueryEscape(client.RedirectURIs[0]) + "&state=xyzDeny"},
		"action":     {"deny"},
	}
	reqDeny := httptest.NewRequest("POST", "/consent", strings.NewReader(denyForm.Encode()))
	reqDeny.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqDeny.AddCookie(&http.Cookie{Name: sm.SessionCookieName(), Value: sessID})
	reqDeny.AddCookie(&http.Cookie{Name: sm.CSRFCookieName(), Value: csrfToken})
	wDeny := httptest.NewRecorder()
	handler.HandleConsent(wDeny, reqDeny)

	if wDeny.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected 302 on consent deny, got %d", wDeny.Result().StatusCode)
	}
	locDeny := wDeny.Result().Header.Get("Location")
	if !strings.Contains(locDeny, "error=access_denied") || !strings.Contains(locDeny, "state=xyzDeny") {
		t.Fatalf("expected access_denied redirect with state, got %q", locDeny)
	}

	// 6. POST /consent action=accept -> saves consent in DB and redirects to return_to
	acceptForm := url.Values{
		"csrf_token": {csrfToken},
		"client_id":  {client.ClientID},
		"scope":      {"openid profile"},
		"return_to":  {"/authorize?client_id=" + client.ClientID},
		"action":     {"accept"},
	}
	reqAccept := httptest.NewRequest("POST", "/consent", strings.NewReader(acceptForm.Encode()))
	reqAccept.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqAccept.AddCookie(&http.Cookie{Name: sm.SessionCookieName(), Value: sessID})
	reqAccept.AddCookie(&http.Cookie{Name: sm.CSRFCookieName(), Value: csrfToken})
	wAccept := httptest.NewRecorder()
	handler.HandleConsent(wAccept, reqAccept)

	if wAccept.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected 302 on consent accept, got %d", wAccept.Result().StatusCode)
	}
	if wAccept.Result().Header.Get("Location") != "/authorize?client_id="+client.ClientID {
		t.Fatalf("expected redirect to return_to, got %q", wAccept.Result().Header.Get("Location"))
	}

	// Verify consent persisted in database
	cRecord, err := s.GetConsent(ctx, user.ID, client.ClientID)
	if err != nil {
		t.Fatalf("expected consent record in DB, got error: %v", err)
	}
	if cRecord.Scope != "openid profile" {
		t.Errorf("expected consented scope 'openid profile', got %q", cRecord.Scope)
	}
}
