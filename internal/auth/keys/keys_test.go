package keys

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func validMasterKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i + 42)
	}
	return k
}

func TestKeyManager_GenerateAndVerify(t *testing.T) {
	mgr, err := NewManager(nil, validMasterKey())
	if err != nil {
		t.Fatalf("failed to create key manager: %v", err)
	}

	key, encryptedPriv, err := mgr.GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	if key.KID == "" {
		t.Error("expected non-empty RFC 7638 thumbprint kid")
	}
	if len(encryptedPriv) == 0 {
		t.Error("expected encrypted private key bytes")
	}

	// Verify decryption of private key
	privDER, err := decryptAESGCM(mgr.masterKey, key.KID, encryptedPriv)
	if err != nil {
		t.Fatalf("failed to decrypt private key: %v", err)
	}
	if len(privDER) == 0 {
		t.Fatal("decrypted DER is empty")
	}

	// Verify wrong AAD fails decryption
	_, err = decryptAESGCM(mgr.masterKey, "wrong-aad", encryptedPriv)
	if err == nil {
		t.Fatal("expected decryption failure with wrong AAD")
	}
}

func TestKeyManager_JWKSNeverSerializesPrivateMembers(t *testing.T) {
	mgr, err := NewManager(nil, validMasterKey())
	if err != nil {
		t.Fatal(err)
	}

	key, _, err := mgr.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	key.Status = StatusActive

	mgr.mu.Lock()
	mgr.cachedKey = key
	mgr.cachedKID = key.KID
	mgr.mu.Unlock()

	jwksBytes, err := mgr.GetPublicJWKS(context.Background())
	if err != nil {
		t.Fatalf("failed to get public JWKS: %v", err)
	}

	var rawMap map[string]any
	if err := json.Unmarshal(jwksBytes, &rawMap); err != nil {
		t.Fatalf("JWKS is not valid JSON: %v", err)
	}

	keysArray, ok := rawMap["keys"].([]any)
	if !ok || len(keysArray) == 0 {
		t.Fatalf("expected non-empty keys array in JWKS: %s", string(jwksBytes))
	}

	firstKey := keysArray[0].(map[string]any)

	// RFC 7518 private RSA members that MUST NEVER be present
	forbiddenPrivateMembers := []string{
		"d",  // private exponent
		"p",  // first prime factor
		"q",  // second prime factor
		"dp", // first factor CRT exponent
		"dq", // second factor CRT exponent
		"qi", // first CRT coefficient
	}

	for _, member := range forbiddenPrivateMembers {
		if _, exists := firstKey[member]; exists {
			t.Errorf("CRITICAL SECURITY VIOLATION: JWKS contains private RSA parameter %q: %s", member, string(jwksBytes))
		}
	}

	// Verify required public members are present
	requiredPublicMembers := []string{"kty", "n", "e", "kid", "alg", "use"}
	for _, pub := range requiredPublicMembers {
		if _, exists := firstKey[pub]; !exists {
			t.Errorf("missing standard public member %q in JWKS: %s", pub, string(jwksBytes))
		}
	}
}

func TestKeyManager_HTTPHandler(t *testing.T) {
	mgr, err := NewManager(nil, validMasterKey())
	if err != nil {
		t.Fatal(err)
	}

	key, _, err := mgr.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	key.Status = StatusActive
	mgr.cachedKey = key

	handler := mgr.Handler()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/jwks.json", nil)

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "public, max-age=300") {
		t.Errorf("expected Cache-Control public, max-age=300, got %q", rec.Header().Get("Cache-Control"))
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("expected application/json, got %q", rec.Header().Get("Content-Type"))
	}
}
