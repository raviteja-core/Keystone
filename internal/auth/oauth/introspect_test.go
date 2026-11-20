package oauth_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/raviteja-core/keystone/internal/auth/oauth"
)

func TestIntrospectHandler_RFC7662(t *testing.T) {
	f := setupFixture(t)
	ih := oauth.NewIntrospectHandler(f.issuer, f.store, f.keyMgr, f.tokenHandler, nil)

	// Issue a real access token using client_credentials grant
	formToken := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"openid profile"},
	}
	reqToken := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(formToken.Encode()))
	reqToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqToken.SetBasicAuth(f.client.ClientID, f.rawSecret)
	recToken := httptest.NewRecorder()
	f.tokenHandler.ServeHTTP(recToken, reqToken)

	if recToken.Code != http.StatusOK {
		b, _ := io.ReadAll(recToken.Body)
		t.Fatalf("failed to obtain access token: %d %s", recToken.Code, string(b))
	}

	var tr oauth.TokenResponse
	if err := json.NewDecoder(recToken.Body).Decode(&tr); err != nil {
		t.Fatalf("failed to decode token response: %v", err)
	}

	// 1. Unauthenticated client -> 401
	form := url.Values{"token": {tr.AccessToken}}
	req := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	ih.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated client, got %d", rec.Code)
	}

	// 2. Authenticated client with active token -> active: true
	req = httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ClientID, f.rawSecret)
	rec = httptest.NewRecorder()
	ih.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp oauth.IntrospectionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse introspection response: %v", err)
	}
	if !resp.Active {
		t.Errorf("expected active = true, got active = false")
	}
	if resp.ClientID != f.client.ClientID {
		t.Errorf("expected client_id %s, got %s", f.client.ClientID, resp.ClientID)
	}
	if resp.TokenType != "at+jwt" {
		t.Errorf("expected token_type at+jwt, got %s", resp.TokenType)
	}

	// 3. Introspect invalid / malformed token -> active: false (HTTP 200)
	formBad := url.Values{"token": {"invalid.jwt.token"}}
	reqBad := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(formBad.Encode()))
	reqBad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqBad.SetBasicAuth(f.client.ClientID, f.rawSecret)
	recBad := httptest.NewRecorder()
	ih.ServeHTTP(recBad, reqBad)

	if recBad.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for invalid token introspection, got %d", recBad.Code)
	}
	var respBad oauth.IntrospectionResponse
	if err := json.Unmarshal(recBad.Body.Bytes(), &respBad); err != nil {
		t.Fatalf("failed to decode response for bad token: %v", err)
	}
	if respBad.Active {
		t.Errorf("expected active = false for invalid token, got true")
	}
}
