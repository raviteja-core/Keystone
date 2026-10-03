package integration

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	"github.com/raviteja-core/keystone/internal/auth/discovery"
	"github.com/raviteja-core/keystone/internal/auth/keys"
	"github.com/raviteja-core/keystone/internal/auth/oauth"
	"github.com/raviteja-core/keystone/internal/auth/password"
	"github.com/raviteja-core/keystone/internal/auth/session"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/auth/token"
	"github.com/raviteja-core/keystone/internal/auth/ui"
	"github.com/raviteja-core/keystone/internal/auth/userinfo"
	"github.com/raviteja-core/keystone/internal/platform/db"
	"github.com/raviteja-core/keystone/internal/platform/httpx"
	"github.com/raviteja-core/keystone/internal/platform/ids"
	"github.com/raviteja-core/keystone/internal/platform/logging"
)

func getE2EPool(t *testing.T) *pgxpool.Pool {
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
		t.Skipf("skipping e2e test: PostgreSQL not available: %v", err)
	}

	return pool
}

func TestE2E_Phase1_HappyPathAndSecurityAudit(t *testing.T) {
	pool := getE2EPool(t)
	ctx := context.Background()

	// 1. Set up in-memory log buffer to capture all logs for secret leakage audit (AS-31)
	var logBuf bytes.Buffer
	logger := logging.NewJSONLogger(&logBuf, slog.LevelDebug)

	issuerURL := "http://localhost:8080"

	masterKeyB64 := os.Getenv("KEYSTONE_MASTER_KEY")
	if masterKeyB64 == "" {
		masterKeyB64 = "ta2vI9UdhLTp7Ak2M33C9oSRrdl6riaCkKFL6UDP6Zc="
	}
	masterKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		masterKey, _ = base64.RawURLEncoding.DecodeString(masterKeyB64)
	}

	authStore := store.New(pool)
	keyMgr, err := keys.NewManager(pool, masterKey)
	if err != nil {
		t.Fatalf("failed to init key manager: %v", err)
	}
	activeKey, err := keyMgr.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatalf("failed to ensure active key: %v", err)
	}

	hasher, err := password.NewHasher(password.DefaultConfig())
	if err != nil {
		t.Fatalf("failed to init hasher: %v", err)
	}

	sessMgr := session.NewManager(authStore, session.Config{
		CookieSecure: false,
		IdleTTL:      30 * time.Minute,
		AbsoluteTTL:  12 * time.Hour,
	})

	tokenValidator := token.NewValidator(issuerURL, "", func(kid string) (*rsa.PublicKey, error) {
		k, err := keyMgr.GetActiveKey(ctx)
		if err != nil || k == nil || k.KID != kid {
			return nil, errors.New("key not found")
		}
		return k.PublicKey, nil
	})

	// Build full HTTP router exactly as authserver
	publicMux := http.NewServeMux()
	publicMux.HandleFunc("GET /.well-known/openid-configuration", discovery.Handler(issuerURL))
	publicMux.HandleFunc("GET /.well-known/oauth-authorization-server", discovery.Handler(issuerURL))
	publicMux.HandleFunc("GET /jwks.json", keyMgr.Handler())

	authorizeHandler := oauth.NewAuthorizeHandler(issuerURL, authStore, sessMgr, 60*time.Second, logger)
	publicMux.Handle("GET /authorize", authorizeHandler)

	tokenHandler := oauth.NewTokenHandler(oauth.TokenConfig{
		Issuer:         issuerURL,
		AccessTokenTTL: 10 * time.Minute,
		IDTokenTTL:     10 * time.Minute,
		RefreshIdleTTL: 24 * time.Hour,
		RefreshAbsTTL:  90 * 24 * time.Hour,
	}, authStore, keyMgr, logger)
	auditWriter := audit.NewWriter(pool)
	tokenHandler.SetAuditWriter(auditWriter)
	publicMux.Handle("POST /token", tokenHandler)

	userinfoHandler := userinfo.NewHandler(tokenValidator, authStore)
	publicMux.Handle("GET /userinfo", userinfoHandler)
	publicMux.Handle("POST /userinfo", userinfoHandler)

	uiHandler := ui.NewHandler(authStore, sessMgr, hasher, auditWriter, logger)
	publicMux.HandleFunc("GET /login", uiHandler.HandleLogin)
	publicMux.HandleFunc("POST /login", uiHandler.HandleLogin)
	publicMux.HandleFunc("GET /register", uiHandler.HandleRegister)
	publicMux.HandleFunc("POST /register", uiHandler.HandleRegister)
	publicMux.HandleFunc("GET /consent", uiHandler.HandleConsent)
	publicMux.HandleFunc("POST /consent", uiHandler.HandleConsent)

	serverHandler := httpx.RequestID(
		httpx.Recover(logger)(
			httpx.AccessLog(logger)(
				httpx.SecurityHeaders(
					httpx.MaxBodyBytes(65536)(publicMux),
				),
			),
		),
	)

	ts := httptest.NewServer(serverHandler)
	defer ts.Close()

	// 2. Register OAuth Client in DB
	cid, _ := ids.NewUUIDv7()
	clientID := "e2e_client_" + cid.String()
	rawSecret, _ := ids.RandomBase64URL(32)
	secretHash := ids.SHA256Digest([]byte(rawSecret))
	callbackURL := "https://client.example.com/oauth/callback"

	client := &store.Client{
		ID:                      cid,
		ClientID:                clientID,
		ClientSecretHash:        secretHash,
		Name:                    "E2E Integration Client",
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{callbackURL},
		AllowedGrantTypes:       []string{"authorization_code", "refresh_token", "client_credentials"},
		AllowedScopes:           []string{"openid", "profile", "email"},
		AllowedAudiences:        []string{"https://api.example.com"},
		RequireConsent:          false,
	}
	if err := authStore.CreateClient(ctx, client); err != nil {
		t.Fatalf("failed to register client: %v", err)
	}

	// 3. User Registration Flow: GET /register to fetch CSRF token, then POST /register
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // do not follow redirects automatically
		},
	}

	regGetResp, err := httpClient.Get(ts.URL + "/register")
	if err != nil {
		t.Fatalf("failed to GET /register: %v", err)
	}
	var csrfCookie *http.Cookie
	for _, c := range regGetResp.Cookies() {
		if c.Name == sessMgr.CSRFCookieName() {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected CSRF cookie from GET /register")
	}

	uid, _ := ids.NewUUIDv7()
	testEmail := "e2e_user_" + uid.String() + "@example.com"
	testPassword := "SuperSecurePassword123!"
	testUsername := "user_" + strings.ReplaceAll(uid.String(), "-", "")

	regForm := url.Values{
		"csrf_token": {csrfCookie.Value},
		"email":      {testEmail},
		"username":   {testUsername},
		"password":   {testPassword},
		"return_to":  {"/authorize"},
	}
	regReq, _ := http.NewRequest("POST", ts.URL+"/register", strings.NewReader(regForm.Encode()))
	regReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	regReq.AddCookie(csrfCookie)

	regPostResp, err := httpClient.Do(regReq)
	if err != nil {
		t.Fatalf("failed to POST /register: %v", err)
	}
	if regPostResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(regPostResp.Body)
		t.Fatalf("expected 302 Found from /register, got %d: %s", regPostResp.StatusCode, string(body))
	}

	// Extract session cookie from registration response
	var sessionCookie *http.Cookie
	for _, c := range regPostResp.Cookies() {
		if c.Name == sessMgr.SessionCookieName() {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected session cookie after registration")
	}

	// 4. Authorization Code Flow: GET /authorize with session cookie
	verifier, _ := ids.RandomBase64URL(48)
	vHash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(vHash[:])

	authParams := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {callbackURL},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"xyzState789"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"nonce":                 {"randomNonce123"},
	}

	authReq, _ := http.NewRequest("GET", ts.URL+"/authorize?"+authParams.Encode(), nil)
	authReq.AddCookie(sessionCookie)

	authResp, err := httpClient.Do(authReq)
	if err != nil {
		t.Fatalf("failed to GET /authorize: %v", err)
	}
	if authResp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(authResp.Body)
		t.Fatalf("expected 302 Found from /authorize, got %d: %s", authResp.StatusCode, string(body))
	}

	authRedirectURL := authResp.Header.Get("Location")
	parsedAuthRedirect, err := url.Parse(authRedirectURL)
	if err != nil {
		t.Fatalf("failed to parse auth redirect URL %q: %v", authRedirectURL, err)
	}

	code := parsedAuthRedirect.Query().Get("code")
	stateEcho := parsedAuthRedirect.Query().Get("state")
	issEcho := parsedAuthRedirect.Query().Get("iss")

	if code == "" {
		t.Fatalf("expected code in redirect URL %q", authRedirectURL)
	}
	if stateEcho != "xyzState789" {
		t.Errorf("expected state echo 'xyzState789', got %q", stateEcho)
	}
	if issEcho != issuerURL {
		t.Errorf("expected iss echo %q, got %q", issuerURL, issEcho)
	}

	// 5. Token Exchange: POST /token
	tokenExchangeForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"code_verifier": {verifier},
	}
	tokenReq, _ := http.NewRequest("POST", ts.URL+"/token", strings.NewReader(tokenExchangeForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(clientID, rawSecret)

	tokenResp, err := httpClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("failed to POST /token: %v", err)
	}
	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("expected 200 OK from /token, got %d: %s", tokenResp.StatusCode, string(body))
	}

	// Verify headers: Cache-Control: no-store, Pragma: no-cache
	if tokenResp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("expected Cache-Control: no-store, got %q", tokenResp.Header.Get("Cache-Control"))
	}
	if tokenResp.Header.Get("Pragma") != "no-cache" {
		t.Errorf("expected Pragma: no-cache, got %q", tokenResp.Header.Get("Pragma"))
	}

	var tokRes oauth.TokenResponse
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokRes); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	if tokRes.AccessToken == "" {
		t.Fatal("expected non-empty access token")
	}
	if tokRes.RefreshToken == "" {
		t.Fatal("expected non-empty refresh token")
	}
	if tokRes.IDToken == "" {
		t.Fatal("expected non-empty ID token")
	}

	// 6. UserInfo Endpoint: GET /userinfo with Bearer token
	userInfoReq, _ := http.NewRequest("GET", ts.URL+"/userinfo", nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+tokRes.AccessToken)

	userInfoResp, err := httpClient.Do(userInfoReq)
	if err != nil {
		t.Fatalf("failed to GET /userinfo: %v", err)
	}
	if userInfoResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userInfoResp.Body)
		t.Fatalf("expected 200 OK from /userinfo, got %d: %s", userInfoResp.StatusCode, string(body))
	}

	var uiRes userinfo.UserInfoResponse
	if err := json.NewDecoder(userInfoResp.Body).Decode(&uiRes); err != nil {
		t.Fatalf("failed to decode userinfo response: %v", err)
	}

	if uiRes.Email != testEmail {
		t.Errorf("expected email %q, got %q", testEmail, uiRes.Email)
	}
	if uiRes.PreferredUsername != testUsername {
		t.Errorf("expected preferred_username %q, got %q", testUsername, uiRes.PreferredUsername)
	}

	// 7. Refresh Token Rotation: POST /token grant_type=refresh_token
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokRes.RefreshToken},
	}
	refreshReq, _ := http.NewRequest("POST", ts.URL+"/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshReq.SetBasicAuth(clientID, rawSecret)

	refreshResp, err := httpClient.Do(refreshReq)
	if err != nil {
		t.Fatalf("failed to refresh token: %v", err)
	}
	if refreshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("expected 200 OK from refresh, got %d: %s", refreshResp.StatusCode, string(body))
	}

	var rotRes oauth.TokenResponse
	if err := json.NewDecoder(refreshResp.Body).Decode(&rotRes); err != nil {
		t.Fatalf("failed to decode rotated token response: %v", err)
	}
	if rotRes.RefreshToken == "" || rotRes.RefreshToken == tokRes.RefreshToken {
		t.Fatal("expected newly rotated refresh token")
	}

	// 8. Replay Detection: Replaying old RT must fail with 400 invalid_grant and revoke family
	replayReq, _ := http.NewRequest("POST", ts.URL+"/token", strings.NewReader(refreshForm.Encode()))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayReq.SetBasicAuth(clientID, rawSecret)

	replayResp, err := httpClient.Do(replayReq)
	if err != nil {
		t.Fatalf("failed to send replay request: %v", err)
	}
	if replayResp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request on refresh token replay, got %d", replayResp.StatusCode)
	}

	// 9. Probe AS-31 & DoD Verification: Scrape all logs produced during the e2e flow
	// No secret, password, auth code, client secret, or token must appear in plaintext logs!
	loggedText := logBuf.String()

	sensitiveSecrets := map[string]string{
		"user password":   testPassword,
		"client secret":   rawSecret,
		"auth code":       code,
		"access token":    tokRes.AccessToken,
		"refresh token 1": tokRes.RefreshToken,
		"refresh token 2": rotRes.RefreshToken,
		"id token":        tokRes.IDToken,
	}

	for secretType, secretVal := range sensitiveSecrets {
		if secretVal != "" && strings.Contains(loggedText, secretVal) {
			t.Errorf("CRITICAL SECURITY VIOLATION (AS-31): Plaintext %s leaked in server logs! Value: %q", secretType, secretVal)
		}
	}

	// 10. Audit Chain Verification & Secret Scan:
	// Verify audit_events table contains records for user.registered, token.issued, refresh_token.reuse_detected
	auditRows, err := pool.Query(ctx, `
		SELECT action, metadata::text, COALESCE(user_agent, ''), COALESCE(request_id, '')
		FROM audit_events
		ORDER BY id DESC LIMIT 50
	`)
	if err != nil {
		t.Fatalf("failed to query audit_events: %v", err)
	}
	defer auditRows.Close()

	foundRegistered := false
	foundTokenIssued := false
	foundReuse := false

	for auditRows.Next() {
		var action, metaText, ua, reqID string
		if err := auditRows.Scan(&action, &metaText, &ua, &reqID); err != nil {
			t.Fatalf("failed to scan audit row: %v", err)
		}
		if action == audit.ActionUserRegistered {
			foundRegistered = true
		}
		if action == audit.ActionTokenIssued {
			foundTokenIssued = true
		}
		if action == audit.ActionRefreshTokenReuse {
			foundReuse = true
		}

		// Ensure no secrets leaked in audit metadata
		combinedMeta := strings.ToLower(metaText + " " + ua + " " + reqID)
		for secretType, secretVal := range sensitiveSecrets {
			if secretVal != "" && strings.Contains(combinedMeta, strings.ToLower(secretVal)) {
				t.Errorf("CRITICAL SECURITY VIOLATION: Secret %s leaked in audit metadata: %s", secretType, metaText)
			}
		}
	}

	if !foundRegistered {
		t.Errorf("expected audit event %q was not found in audit_events table", audit.ActionUserRegistered)
	}
	if !foundTokenIssued {
		t.Errorf("expected audit event %q was not found in audit_events table", audit.ActionTokenIssued)
	}
	if !foundReuse {
		t.Errorf("expected audit event %q was not found in audit_events table", audit.ActionRefreshTokenReuse)
	}

	_ = activeKey
}
