package oauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	"github.com/raviteja-core/keystone/internal/auth/keys"
	"github.com/raviteja-core/keystone/internal/auth/oauth"
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
		t.Skipf("skipping OAuth test: PostgreSQL not available: %v", err)
	}

	return pool
}

type testFixture struct {
	issuer       string
	store        *store.Store
	sessionMgr   *session.Manager
	keyMgr       *keys.Manager
	authHandler  *oauth.AuthorizeHandler
	tokenHandler *oauth.TokenHandler
	client       *store.Client
	rawSecret    string
	user         *store.User
}

func setupFixture(t *testing.T) *testFixture {
	t.Helper()
	pool := getTestPool(t)
	s := store.New(pool)
	sm := session.NewManager(s, session.Config{CookieSecure: false})

	masterKeyB64 := os.Getenv("KEYSTONE_MASTER_KEY")
	if masterKeyB64 == "" {
		masterKeyB64 = "ta2vI9UdhLTp7Ak2M33C9oSRrdl6riaCkKFL6UDP6Zc="
	}
	decodedKey, err := base64.StdEncoding.DecodeString(masterKeyB64)
	if err != nil {
		decodedKey, _ = base64.RawURLEncoding.DecodeString(masterKeyB64)
	}
	km, err := keys.NewManager(pool, decodedKey)
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}
	ctx := context.Background()
	_, err = km.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatalf("failed to ensure active key: %v", err)
	}

	issuer := "http://localhost:8080"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	authH := oauth.NewAuthorizeHandler(issuer, s, sm, 60*time.Second, logger)
	tokH := oauth.NewTokenHandler(oauth.TokenConfig{
		Issuer:         issuer,
		AccessTokenTTL: 10 * time.Minute,
		IDTokenTTL:     10 * time.Minute,
		RefreshIdleTTL: 24 * time.Hour,
		RefreshAbsTTL:  90 * 24 * time.Hour,
	}, s, km, logger)

	// Create confidential client
	cid, _ := ids.NewUUIDv7()
	clientID := "oauth_client_" + cid.String()
	rawSecret, _ := ids.RandomBase64URL(32)
	secretHash := ids.SHA256Digest([]byte(rawSecret))

	client := &store.Client{
		ID:                      cid,
		ClientID:                clientID,
		ClientSecretHash:        secretHash,
		Name:                    "OAuth Test Client",
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://app.example.com/oauth/callback"},
		AllowedGrantTypes:       []string{"authorization_code", "client_credentials", "refresh_token"},
		AllowedScopes:           []string{"openid", "profile", "email"},
		AllowedAudiences:        []string{"https://api.example.com"},
		RequireConsent:          false,
	}
	if err := s.CreateClient(ctx, client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Create user
	uid, _ := ids.NewUUIDv7()
	user := &store.User{
		ID:           uid,
		Email:        "oauth_user_" + uid.String() + "@example.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$test$test",
	}
	if err := s.CreateUser(ctx, user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	return &testFixture{
		issuer:       issuer,
		store:        s,
		sessionMgr:   sm,
		keyMgr:       km,
		authHandler:  authH,
		tokenHandler: tokH,
		client:       client,
		rawSecret:    rawSecret,
		user:         user,
	}
}

// -------------------------------------------------------------------------
// /authorize Tests
// -------------------------------------------------------------------------

func TestOAuth_Authorize_Validation(t *testing.T) {
	f := setupFixture(t)

	// AS-07: Unknown client_id -> 400 error page, NO redirect
	reqNoClient := httptest.NewRequest("GET", "/authorize?client_id=nonexistent&redirect_uri=https://app.example.com/oauth/callback", nil)
	wNoClient := httptest.NewRecorder()
	f.authHandler.ServeHTTP(wNoClient, reqNoClient)
	if wNoClient.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("AS-07: expected 400 on unknown client, got %d", wNoClient.Result().StatusCode)
	}
	if wNoClient.Result().Header.Get("Location") != "" {
		t.Errorf("AS-07: expected NO redirect on unknown client, got %q", wNoClient.Result().Header.Get("Location"))
	}

	// AS-06: redirect_uri variants -> 400 error page, NO redirect
	invalidURIs := []string{
		"https://app.example.com/oauth/callback/",             // trailing slash
		"https://APP.EXAMPLE.COM/oauth/callback",              // uppercase host
		"https://app.example.com/oauth/callback?extra=1",      // extra query
		"https://app.example.com:8443/oauth/callback",         // different port
		"https://app.example.com/oauth/callback@evil.example", // authority injection
		"https://app.example.com/oauth/callback/../evil",      // path traversal
		"http://app.example.com/oauth/callback",               // scheme change
	}
	for _, badURI := range invalidURIs {
		u := "/authorize?client_id=" + f.client.ClientID + "&redirect_uri=" + url.QueryEscape(badURI)
		reqBadURI := httptest.NewRequest("GET", u, nil)
		wBadURI := httptest.NewRecorder()
		f.authHandler.ServeHTTP(wBadURI, reqBadURI)
		if wBadURI.Result().StatusCode != http.StatusBadRequest {
			t.Errorf("AS-06: expected 400 on bad redirect_uri %q, got %d", badURI, wBadURI.Result().StatusCode)
		}
		if wBadURI.Result().Header.Get("Location") != "" {
			t.Errorf("AS-06: expected NO redirect on bad redirect_uri %q, got %q", badURI, wBadURI.Result().Header.Get("Location"))
		}
	}

	baseParams := url.Values{
		"client_id":             {f.client.ClientID},
		"redirect_uri":          {f.client.RedirectURIs[0]},
		"state":                 {"xyz123"},
		"scope":                 {"openid"},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
	}

	cloneParams := func() url.Values {
		v := url.Values{}
		for k, list := range baseParams {
			for _, val := range list {
				v.Add(k, val)
			}
		}
		return v
	}

	// AS-08: response_type=token -> redirect with error=unsupported_response_type
	tokenTypeParams := cloneParams()
	tokenTypeParams.Set("response_type", "token")
	reqToken := httptest.NewRequest("GET", "/authorize?"+tokenTypeParams.Encode(), nil)
	wToken := httptest.NewRecorder()
	f.authHandler.ServeHTTP(wToken, reqToken)
	loc := wToken.Result().Header.Get("Location")
	if !strings.Contains(loc, "error=unsupported_response_type") {
		t.Errorf("AS-08: expected error=unsupported_response_type in redirect, got %q", loc)
	}

	// AS-01: missing code_challenge -> redirect with error=invalid_request
	noPKCE := cloneParams()
	noPKCE.Del("code_challenge")
	reqNoPKCE := httptest.NewRequest("GET", "/authorize?"+noPKCE.Encode(), nil)
	wNoPKCE := httptest.NewRecorder()
	f.authHandler.ServeHTTP(wNoPKCE, reqNoPKCE)
	locPKCE := wNoPKCE.Result().Header.Get("Location")
	if !strings.Contains(locPKCE, "error=invalid_request") {
		t.Errorf("AS-01: expected error=invalid_request for missing PKCE, got %q", locPKCE)
	}

	// AS-02: code_challenge_method=plain -> redirect with error=invalid_request
	plainPKCE := cloneParams()
	plainPKCE.Set("code_challenge_method", "plain")
	reqPlain := httptest.NewRequest("GET", "/authorize?"+plainPKCE.Encode(), nil)
	wPlain := httptest.NewRecorder()
	f.authHandler.ServeHTTP(wPlain, reqPlain)
	locPlain := wPlain.Result().Header.Get("Location")
	if !strings.Contains(locPlain, "error=invalid_request") {
		t.Errorf("AS-02: expected error=invalid_request for plain PKCE, got %q", locPlain)
	}

	// AS-38: prompt=none without active session -> login_required redirect (no UI)
	noneParams := cloneParams()
	noneParams.Set("prompt", "none")
	reqPromptNone := httptest.NewRequest("GET", "/authorize?"+noneParams.Encode(), nil)
	wPromptNone := httptest.NewRecorder()
	f.authHandler.ServeHTTP(wPromptNone, reqPromptNone)
	locNone := wPromptNone.Result().Header.Get("Location")
	if !strings.Contains(locNone, "error=login_required") {
		t.Errorf("AS-38: expected login_required error redirect for prompt=none without session, got %q", locNone)
	}
}

func TestOAuth_Authorize_HappyPathWithIssAndState(t *testing.T) {
	f := setupFixture(t)

	// Create active session
	wSess := httptest.NewRecorder()
	reqSess := httptest.NewRequest("GET", "/", nil)
	sessID, _, err := f.sessionMgr.CreateSession(wSess, reqSess, f.user.ID, []string{"pwd"})
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	params := url.Values{
		"client_id":             {f.client.ClientID},
		"redirect_uri":          {f.client.RedirectURIs[0]},
		"state":                 {"mystate123"},
		"scope":                 {"openid email"},
		"response_type":         {"code"},
		"code_challenge_method": {"S256"},
		"code_challenge":        {challenge},
	}

	reqAuth := httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil)
	reqAuth.AddCookie(&http.Cookie{
		Name:  f.sessionMgr.SessionCookieName(),
		Value: sessID,
	})
	wAuth := httptest.NewRecorder()

	f.authHandler.ServeHTTP(wAuth, reqAuth)
	resp := wAuth.Result()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", resp.StatusCode)
	}

	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("failed to parse redirect location %q: %v", loc, err)
	}

	q := u.Query()
	code := q.Get("code")
	state := q.Get("state")
	iss := q.Get("iss")

	if code == "" {
		t.Fatal("expected authorization code in redirect query")
	}
	// AS-10: state and iss present
	if state != "mystate123" {
		t.Errorf("AS-10: expected state mystate123, got %q", state)
	}
	if iss != f.issuer {
		t.Errorf("AS-10: expected iss %q, got %q", f.issuer, iss)
	}

	// ---------------------------------------------------------------------
	// Token Endpoint Exchange (authorization_code grant)
	// ---------------------------------------------------------------------

	// AS-16: Response headers check
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.client.RedirectURIs[0]},
		"code_verifier": {verifier},
	}
	reqToken := httptest.NewRequest("POST", "/token", strings.NewReader(tokenForm.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqToken.SetBasicAuth(f.client.ClientID, f.rawSecret)
	wToken := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wToken, reqToken)
	tokenResp := wToken.Result()

	// AS-16: Cache-Control: no-store, Pragma: no-cache
	if tokenResp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("AS-16: expected Cache-Control: no-store, got %q", tokenResp.Header.Get("Cache-Control"))
	}
	if tokenResp.Header.Get("Pragma") != "no-cache" {
		t.Errorf("AS-16: expected Pragma: no-cache, got %q", tokenResp.Header.Get("Pragma"))
	}

	if tokenResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("expected token exchange 200 OK, got %d: %s", tokenResp.StatusCode, string(b))
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
		t.Fatal("expected non-empty ID token for openid scope")
	}

	// AS-11: Refresh token rotation and reuse detection
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokRes.RefreshToken},
	}
	reqRefresh := httptest.NewRequest("POST", "/token", strings.NewReader(refreshForm.Encode()))
	reqRefresh.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqRefresh.SetBasicAuth(f.client.ClientID, f.rawSecret)
	wRefresh := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wRefresh, reqRefresh)
	if wRefresh.Result().StatusCode != http.StatusOK {
		b, _ := io.ReadAll(wRefresh.Body)
		t.Fatalf("expected refresh 200 OK, got %d: %s", wRefresh.Result().StatusCode, string(b))
	}

	var refRes oauth.TokenResponse
	_ = json.NewDecoder(wRefresh.Body).Decode(&refRes)
	if refRes.RefreshToken == "" || refRes.RefreshToken == tokRes.RefreshToken {
		t.Fatal("expected rotated new refresh token")
	}

	// Replay RT1 -> must fail and revoke family
	reqRT1Replay := httptest.NewRequest("POST", "/token", strings.NewReader(refreshForm.Encode()))
	reqRT1Replay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqRT1Replay.SetBasicAuth(f.client.ClientID, f.rawSecret)
	wRT1Replay := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wRT1Replay, reqRT1Replay)
	if wRT1Replay.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("AS-11: expected 400 on RT1 replay, got %d", wRT1Replay.Result().StatusCode)
	}

	// RT2 must now also be rejected
	rt2Form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refRes.RefreshToken},
	}
	reqRT2 := httptest.NewRequest("POST", "/token", strings.NewReader(rt2Form.Encode()))
	reqRT2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqRT2.SetBasicAuth(f.client.ClientID, f.rawSecret)
	wRT2 := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wRT2, reqRT2)
	if wRT2.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("AS-11: expected RT2 rejected after family revocation, got %d", wRT2.Result().StatusCode)
	}

	// AS-04: Code reuse detection (replaying the original authorization code)
	reqReplay := httptest.NewRequest("POST", "/token", strings.NewReader(tokenForm.Encode()))
	reqReplay.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqReplay.SetBasicAuth(f.client.ClientID, f.rawSecret)
	wReplay := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wReplay, reqReplay)
	if wReplay.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("AS-04: expected 400 Bad Request on code reuse, got %d", wReplay.Result().StatusCode)
	}
}

func TestOAuth_ClientCredentialsGrant(t *testing.T) {
	f := setupFixture(t)

	// Happy path: client_credentials for confidential client
	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid profile"},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ClientID, f.rawSecret)
	w := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(w, req)
	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 OK for client_credentials, got %d: %s", resp.StatusCode, string(b))
	}

	var tr oauth.TokenResponse
	_ = json.NewDecoder(resp.Body).Decode(&tr)

	if tr.AccessToken == "" {
		t.Fatal("expected access token")
	}
	// No refresh token or ID token for client_credentials
	if tr.RefreshToken != "" {
		t.Errorf("client_credentials MUST NOT return refresh_token, got %q", tr.RefreshToken)
	}
	if tr.IDToken != "" {
		t.Errorf("client_credentials MUST NOT return id_token, got %q", tr.IDToken)
	}

	// AS-15: Client credentials with wrong secret -> 401 invalid_client
	reqBadSec := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	reqBadSec.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBadSec.SetBasicAuth(f.client.ClientID, "wrong-secret")
	wBadSec := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wBadSec, reqBadSec)
	if wBadSec.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("AS-15: expected 401 Unauthorized on wrong secret, got %d", wBadSec.Result().StatusCode)
	}

	// AS-15: Credentials in both header and body -> 400 invalid_request
	bothForm := form
	bothForm.Set("client_id", f.client.ClientID)
	bothForm.Set("client_secret", f.rawSecret)
	reqBoth := httptest.NewRequest("POST", "/token", strings.NewReader(bothForm.Encode()))
	reqBoth.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBoth.SetBasicAuth(f.client.ClientID, f.rawSecret)
	wBoth := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wBoth, reqBoth)
	if wBoth.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("AS-15: expected 400 on credentials in both header and body, got %d", wBoth.Result().StatusCode)
	}

	// AS-09: Unsupported grant type (password) -> 400 unsupported_grant_type
	pwdForm := url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"password":   {"secret"},
	}
	reqPwd := httptest.NewRequest("POST", "/token", strings.NewReader(pwdForm.Encode()))
	reqPwd.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqPwd.SetBasicAuth(f.client.ClientID, f.rawSecret)
	wPwd := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wPwd, reqPwd)
	if wPwd.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("AS-09: expected 400 on password grant, got %d", wPwd.Result().StatusCode)
	}
}

func TestOAuth_RefreshToken_ScopeWideningAndDifferentClient(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	// Create an initial refresh token with scope "openid"
	rtRaw, _ := ids.RandomBase64URL(32)
	rtHash := ids.SHA256Digest([]byte(rtRaw))
	rtID, _ := ids.NewUUIDv7()
	famID, _ := ids.NewUUIDv7()
	now := time.Now()

	rtRecord := &store.RefreshToken{
		ID:                rtID,
		TokenHash:         rtHash,
		FamilyID:          famID,
		ClientID:          f.client.ClientID,
		UserID:            f.user.ID,
		Scope:             "openid",
		IssuedAt:          now,
		ExpiresAt:         now.Add(24 * time.Hour),
		AbsoluteExpiresAt: now.Add(90 * 24 * time.Hour),
	}
	if err := f.store.CreateRefreshToken(ctx, rtRecord); err != nil {
		t.Fatalf("failed to create refresh token: %v", err)
	}

	// AS-13: Refresh with broader scope ("openid admin:all") -> 400 invalid_scope
	widenForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rtRaw},
		"scope":         {"openid admin:all"},
	}
	reqWiden := httptest.NewRequest("POST", "/token", strings.NewReader(widenForm.Encode()))
	reqWiden.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqWiden.SetBasicAuth(f.client.ClientID, f.rawSecret)
	wWiden := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wWiden, reqWiden)
	if wWiden.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("AS-13: expected 400 Bad Request on scope widening, got %d", wWiden.Result().StatusCode)
	}

	// AS-14: Refresh token presented by a DIFFERENT client -> 400 invalid_grant
	otherCID, _ := ids.NewUUIDv7()
	otherSecret, _ := ids.RandomBase64URL(32)
	otherClient := &store.Client{
		ID:                      otherCID,
		ClientID:                "other_client_" + otherCID.String(),
		ClientSecretHash:        ids.SHA256Digest([]byte(otherSecret)),
		Name:                    "Other Client",
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		AllowedGrantTypes:       []string{"refresh_token"},
		AllowedScopes:           []string{"openid"},
	}
	if err := f.store.CreateClient(ctx, otherClient); err != nil {
		t.Fatalf("failed to create other client: %v", err)
	}

	reqOtherClient := httptest.NewRequest("POST", "/token", strings.NewReader(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rtRaw},
	}.Encode()))
	reqOtherClient.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqOtherClient.SetBasicAuth(otherClient.ClientID, otherSecret)
	wOtherClient := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(wOtherClient, reqOtherClient)
	if wOtherClient.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("AS-14: expected 400 invalid_grant when presented by different client, got %d", wOtherClient.Result().StatusCode)
	}
}

func TestOAuth_ExpiredAuthCode_AS37(t *testing.T) {
	f := setupFixture(t)
	ctx := context.Background()

	codeRaw, _ := ids.RandomBase64URL(32)
	codeHash := ids.SHA256Digest([]byte(codeRaw))
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	// Expired 10 seconds ago
	authCode := &store.AuthorizationCode{
		CodeHash:      codeHash,
		ClientID:      f.client.ClientID,
		UserID:        f.user.ID,
		RedirectURI:   f.client.RedirectURIs[0],
		Scope:         "openid",
		CodeChallenge: challenge,
		AuthTime:      time.Now().Add(-1 * time.Hour),
		AMR:           []string{"pwd"},
		ExpiresAt:     time.Now().Add(-10 * time.Second),
		CreatedAt:     time.Now().Add(-1 * time.Hour),
	}
	if err := f.store.CreateAuthCode(ctx, authCode); err != nil {
		t.Fatalf("failed to create expired auth code: %v", err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {codeRaw},
		"redirect_uri":  {f.client.RedirectURIs[0]},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ClientID, f.rawSecret)
	w := httptest.NewRecorder()

	f.tokenHandler.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("AS-37: expected 400 Bad Request on expired auth code, got %d", w.Result().StatusCode)
	}
	var errResp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&errResp)
	if errResp["error"] != "invalid_grant" {
		t.Errorf("AS-37: expected error=invalid_grant, got %q", errResp["error"])
	}
}
