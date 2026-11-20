package oauth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/raviteja-core/keystone/internal/auth/oauth"
)

func TestRevokeHandler_RFC7009(t *testing.T) {
	f := setupFixture(t)
	rh := oauth.NewRevokeHandler(f.store, f.tokenHandler, nil)

	// 1. Unauthenticated client -> 401
	form := url.Values{"token": {"refresh-tok-1"}}
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	rh.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated client, got %d", rec.Code)
	}

	// 2. Authenticated client with token -> 200 OK (RFC 7009 requirement)
	req = httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ClientID, f.rawSecret)
	rec = httptest.NewRecorder()
	rh.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for valid revocation, got %d", rec.Code)
	}

	// 3. Invalid token submitted -> MUST still return 200 OK per RFC 7009 §2.2
	formInvalid := url.Values{"token": {"non-existent-token"}}
	req = httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(formInvalid.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(f.client.ClientID, f.rawSecret)
	rec = httptest.NewRecorder()
	rh.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for unknown token revocation per RFC 7009, got %d", rec.Code)
	}
}
