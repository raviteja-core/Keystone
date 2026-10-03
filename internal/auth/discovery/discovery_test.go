package discovery_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/raviteja-core/keystone/internal/auth/discovery"
)

func TestDiscovery_Handler(t *testing.T) {
	issuer := "http://localhost:8080"
	handler := discovery.Handler(issuer)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected Access-Control-Allow-Origin *, got %q", resp.Header.Get("Access-Control-Allow-Origin"))
	}

	var meta discovery.Metadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode metadata json: %v", err)
	}

	if meta.Issuer != issuer {
		t.Errorf("expected issuer %q, got %q", issuer, meta.Issuer)
	}
	if meta.AuthorizationEndpoint != issuer+"/authorize" {
		t.Errorf("expected authorization_endpoint %q, got %q", issuer+"/authorize", meta.AuthorizationEndpoint)
	}
	if meta.TokenEndpoint != issuer+"/token" {
		t.Errorf("expected token_endpoint %q, got %q", issuer+"/token", meta.TokenEndpoint)
	}
	if meta.JwksURI != issuer+"/jwks.json" {
		t.Errorf("expected jwks_uri %q, got %q", issuer+"/jwks.json", meta.JwksURI)
	}
	if meta.UserinfoEndpoint != issuer+"/userinfo" {
		t.Errorf("expected userinfo_endpoint %q, got %q", issuer+"/userinfo", meta.UserinfoEndpoint)
	}

	// Must support RS256 only
	if len(meta.IDTokenSigningAlgValuesSupported) != 1 || meta.IDTokenSigningAlgValuesSupported[0] != "RS256" {
		t.Errorf("expected RS256 in id_token_signing_alg_values_supported, got %v", meta.IDTokenSigningAlgValuesSupported)
	}

	// Must support S256 only
	if len(meta.CodeChallengeMethodsSupported) != 1 || meta.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("expected S256 in code_challenge_methods_supported, got %v", meta.CodeChallengeMethodsSupported)
	}
}
