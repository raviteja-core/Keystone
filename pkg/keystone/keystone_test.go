package keystone_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/raviteja-core/keystone/pkg/keystone"
)

type testHarness struct {
	privKey *rsa.PrivateKey
	pubKey  *rsa.PublicKey
	kid     string
	jwk     jose.JSONWebKey
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	jwk := jose.JSONWebKey{
		Key:       &priv.PublicKey,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}
	tb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("failed to compute thumbprint: %v", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(tb)
	jwk.KeyID = kid

	return &testHarness{
		privKey: priv,
		pubKey:  &priv.PublicKey,
		kid:     kid,
		jwk:     jwk,
	}
}

func (h *testHarness) signToken(t *testing.T, claims map[string]interface{}, typ string) string {
	t.Helper()
	if typ == "" {
		typ = "at+jwt"
	}
	key := jose.SigningKey{
		Algorithm: jose.RS256,
		Key: &jose.JSONWebKey{
			Key:   h.privKey,
			KeyID: h.kid,
		},
	}
	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("failed to marshal claims: %v", err)
	}

	signed, err := signer.Sign(claimsBytes)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}

	ser, err := signed.CompactSerialize()
	if err != nil {
		t.Fatalf("failed to serialize token: %v", err)
	}
	return ser
}

func standardClaims(iss, aud, sub string) map[string]interface{} {
	now := time.Now().Unix()
	return map[string]interface{}{
		"iss":       iss,
		"sub":       sub,
		"aud":       []string{aud},
		"client_id": "test-client",
		"scope":     "read write documents",
		"jti":       "test-jti-12345",
		"iat":       now,
		"exp":       now + 3600,
	}
}

// ---------------------------------------------------------------------------
// 1. Verifier Tests
// ---------------------------------------------------------------------------

func TestVerifier_ValidToken(t *testing.T) {
	h := newTestHarness(t)
	iss := "https://auth.example.com"
	aud := "https://api.example.com"

	verifier, err := keystone.NewVerifier(iss, aud,
		keystone.WithKeyProvider(func(ctx context.Context, kid string) (*rsa.PublicKey, error) {
			if kid == h.kid {
				return h.pubKey, nil
			}
			return nil, errors.New("key not found")
		}),
	)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	claims := standardClaims(iss, aud, "alice")
	tokenStr := h.signToken(t, claims, "at+jwt")

	vClaims, err := verifier.Verify(context.Background(), tokenStr)
	if err != nil {
		t.Fatalf("expected verify success, got: %v", err)
	}

	if vClaims.Subject != "alice" {
		t.Errorf("expected subject alice, got %s", vClaims.Subject)
	}
	if vClaims.Issuer != iss {
		t.Errorf("expected issuer %s, got %s", iss, vClaims.Issuer)
	}
	if !vClaims.HasScope("read") || !vClaims.HasScope("write") {
		t.Errorf("expected scopes read & write, got %s", vClaims.Scope)
	}
	if vClaims.HasScope("admin") {
		t.Errorf("did not expect scope admin")
	}
}

func TestVerifier_AlgorithmConfusionDefense(t *testing.T) {
	h := newTestHarness(t)
	iss := "https://auth.example.com"
	aud := "https://api.example.com"

	verifier, err := keystone.NewVerifier(iss, aud,
		keystone.WithKeyProvider(func(ctx context.Context, kid string) (*rsa.PublicKey, error) {
			return h.pubKey, nil
		}),
	)
	if err != nil {
		t.Fatalf("failed to create verifier: %v", err)
	}

	// Forge an HMAC-SHA256 token signed using the RSA public key DER bytes as secret
	pubDER := h.pubKey.N.Bytes()
	key := jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       pubDER,
	}
	signer, err := jose.NewSigner(key, (&jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": h.kid,
		},
	}).WithType("at+jwt"))
	if err != nil {
		t.Fatalf("failed to create HMAC signer: %v", err)
	}

	claimsBytes, _ := json.Marshal(standardClaims(iss, aud, "attacker"))
	signed, err := signer.Sign(claimsBytes)
	if err != nil {
		t.Fatalf("failed to sign token: %v", err)
	}
	forgedToken, _ := signed.CompactSerialize()

	// Verification MUST fail
	_, err = verifier.Verify(context.Background(), forgedToken)
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FLAW: alg-confusion token was accepted!")
	}
	if !errors.Is(err, keystone.ErrInvalidAlgorithm) && !errors.Is(err, keystone.ErrInvalidToken) {
		t.Logf("correctly rejected alg-confusion token with: %v", err)
	}
}

func TestVerifier_RejectAlgNone(t *testing.T) {
	iss := "https://auth.example.com"
	aud := "https://api.example.com"

	verifier, _ := keystone.NewVerifier(iss, aud,
		keystone.WithKeyProvider(func(ctx context.Context, kid string) (*rsa.PublicKey, error) {
			return nil, nil
		}),
	)

	// Construct raw alg=none JWT
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"at+jwt","kid":"none"}`))
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://auth.example.com","aud":["https://api.example.com"],"sub":"eve","exp":2000000000}`))
	noneToken := hdr + "." + claims + "."

	_, err := verifier.Verify(context.Background(), noneToken)
	if err == nil {
		t.Fatalf("CRITICAL SECURITY FLAW: alg=none token was accepted!")
	}
	t.Logf("correctly rejected alg=none: %v", err)
}

func TestVerifier_RejectInvalidTokenType(t *testing.T) {
	h := newTestHarness(t)
	iss := "https://auth.example.com"
	aud := "https://api.example.com"

	verifier, _ := keystone.NewVerifier(iss, aud,
		keystone.WithKeyProvider(func(ctx context.Context, kid string) (*rsa.PublicKey, error) {
			return h.pubKey, nil
		}),
	)

	// An ID token (typ: JWT instead of at+jwt) MUST be rejected as an access token
	claims := standardClaims(iss, aud, "alice")
	idToken := h.signToken(t, claims, "JWT")

	_, err := verifier.Verify(context.Background(), idToken)
	if err == nil {
		t.Fatalf("expected error for typ=JWT, but token was accepted")
	}
	if !errors.Is(err, keystone.ErrInvalidTokenType) {
		t.Errorf("expected ErrInvalidTokenType, got: %v", err)
	}
}

func TestVerifier_RejectExpiredToken(t *testing.T) {
	h := newTestHarness(t)
	iss := "https://auth.example.com"
	aud := "https://api.example.com"

	verifier, _ := keystone.NewVerifier(iss, aud,
		keystone.WithClockSkew(5*time.Second),
		keystone.WithKeyProvider(func(ctx context.Context, kid string) (*rsa.PublicKey, error) {
			return h.pubKey, nil
		}),
	)

	claims := standardClaims(iss, aud, "alice")
	claims["exp"] = time.Now().Add(-1 * time.Hour).Unix()
	expiredToken := h.signToken(t, claims, "at+jwt")

	_, err := verifier.Verify(context.Background(), expiredToken)
	if err == nil {
		t.Fatalf("expected error for expired token, but token was accepted")
	}
	if !errors.Is(err, keystone.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got: %v", err)
	}
}

func TestVerifier_RejectWrongAudienceAndIssuer(t *testing.T) {
	h := newTestHarness(t)
	iss := "https://auth.example.com"
	aud := "https://api.example.com"

	verifier, _ := keystone.NewVerifier(iss, aud,
		keystone.WithKeyProvider(func(ctx context.Context, kid string) (*rsa.PublicKey, error) {
			return h.pubKey, nil
		}),
	)

	// Wrong issuer
	claimsWrongIss := standardClaims("https://evil.example.com", aud, "alice")
	t1 := h.signToken(t, claimsWrongIss, "at+jwt")
	if _, err := verifier.Verify(context.Background(), t1); !errors.Is(err, keystone.ErrInvalidIssuer) {
		t.Errorf("expected ErrInvalidIssuer, got: %v", err)
	}

	// Wrong audience
	claimsWrongAud := standardClaims(iss, "https://other-service.example.com", "alice")
	t2 := h.signToken(t, claimsWrongAud, "at+jwt")
	if _, err := verifier.Verify(context.Background(), t2); !errors.Is(err, keystone.ErrInvalidAudience) {
		t.Errorf("expected ErrInvalidAudience, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2. JWKS Remote Cache & Rate Limiting Tests
// ---------------------------------------------------------------------------

func TestJWKSCache_RemoteFetchAndRateLimiting(t *testing.T) {
	h := newTestHarness(t)
	var fetchCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&fetchCount, 1)
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{h.jwk},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cache := keystone.NewJWKSCache(server.URL, server.Client(), 10*time.Minute, 100*time.Millisecond)

	// Initial fetch
	key, err := cache.GetKey(context.Background(), h.kid)
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}
	if key == nil {
		t.Fatalf("expected non-nil key")
	}
	if atomic.LoadInt64(&fetchCount) != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Second request for same kid -> cached, fetchCount remains 1
	key2, err := cache.GetKey(context.Background(), h.kid)
	if err != nil || key2 == nil {
		t.Fatalf("failed second lookup: %v", err)
	}
	if atomic.LoadInt64(&fetchCount) != 1 {
		t.Errorf("expected cache hit with 1 fetch, got %d", fetchCount)
	}

	// Unknown kid -> triggers rate-limited check
	_, err = cache.GetKey(context.Background(), "bogus-kid-1")
	if err == nil {
		t.Fatalf("expected error for bogus kid")
	}

	// Immediate second unknown kid -> rate-limited without calling server
	initialFetches := atomic.LoadInt64(&fetchCount)
	_, _ = cache.GetKey(context.Background(), "bogus-kid-2")
	if atomic.LoadInt64(&fetchCount) > initialFetches {
		t.Errorf("rate limiting should prevent immediate re-fetch for unknown kids")
	}
}

// ---------------------------------------------------------------------------
// 3. Auth Middleware Tests
// ---------------------------------------------------------------------------

func TestAuthMiddleware(t *testing.T) {
	h := newTestHarness(t)
	iss := "https://auth.example.com"
	aud := "https://api.example.com"

	verifier, _ := keystone.NewVerifier(iss, aud,
		keystone.WithKeyProvider(func(ctx context.Context, kid string) (*rsa.PublicKey, error) {
			return h.pubKey, nil
		}),
	)

	mw := keystone.Middleware(verifier, keystone.WithRequiredScope("read"))

	var capturedSubject string
	var capturedScope string
	var capturedRawToken string

	targetHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := keystone.ClaimsFromContext(r.Context())
		if !ok {
			t.Errorf("claims missing in context")
		} else {
			capturedSubject = claims.Subject
			capturedScope = claims.Scope
		}
		raw, ok := keystone.RawTokenFromContext(r.Context())
		if ok {
			capturedRawToken = raw
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	handler := mw(targetHandler)

	// Case 1: Missing Authorization Header
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing header, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "Bearer") {
		t.Errorf("expected WWW-Authenticate: Bearer header")
	}

	// Case 2: Malformed Header
	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for non-Bearer auth, got %d", rec.Code)
	}

	// Case 3: Valid Token with Required Scope
	claims := standardClaims(iss, aud, "bob")
	claims["scope"] = "read write"
	validToken := h.signToken(t, claims, "at+jwt")

	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid token, got %d: %s", rec.Code, rec.Body.String())
	}
	if capturedSubject != "bob" {
		t.Errorf("expected captured subject bob, got %s", capturedSubject)
	}
	if capturedScope != "read write" {
		t.Errorf("expected captured scope 'read write', got %s", capturedScope)
	}
	if capturedRawToken != validToken {
		t.Errorf("expected raw token preserved in context")
	}

	// Case 4: Valid Token Lacking Required Scope -> 403 Forbidden
	claimsNoScope := standardClaims(iss, aud, "carol")
	claimsNoScope["scope"] = "write" // lacks "read"
	noScopeToken := h.signToken(t, claimsNoScope, "at+jwt")

	req = httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer "+noScopeToken)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing scope, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), "insufficient_scope") {
		t.Errorf("expected WWW-Authenticate with insufficient_scope, got %s", rec.Header().Get("WWW-Authenticate"))
	}
}

// ---------------------------------------------------------------------------
// 4. Authz Client & Zookie Propagation Tests
// ---------------------------------------------------------------------------

func TestAuthzClient_CheckAndZookies(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		if authHdr != "Bearer mock-authz-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch r.URL.Path {
		case "/v1/check":
			var req map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&req)
			obj, _ := req["object"].(map[string]interface{})
			id, _ := obj["id"].(string)

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Keystone-Zookie", "zk:tenant1:rev10")

			if id == "allowed-doc" {
				_ = json.NewEncoder(w).Encode(keystone.CheckResponse{
					Allowed:   true,
					CheckedAt: "2026-11-20T10:00:00Z",
					Evaluation: keystone.Evaluation{
						Depth:   2,
						DBReads: 1,
					},
				})
			} else {
				_ = json.NewEncoder(w).Encode(keystone.CheckResponse{
					Allowed:   false,
					CheckedAt: "2026-11-20T10:00:00Z",
				})
			}

		case "/v1/relationships/write":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(keystone.WriteRelationshipsResponse{
				Zookie: "zk:tenant1:rev11",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockServer.Close()

	client, err := keystone.NewAuthzClient(
		mockServer.URL,
		keystone.StaticTokenSource("mock-authz-token"),
		keystone.WithAuthzHTTPClient(mockServer.Client()),
	)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// 1. Check allowed
	resp, err := client.Check(context.Background(), keystone.CheckRequest{
		Object:     keystone.ObjectRef{Type: "document", ID: "allowed-doc"},
		Permission: "view",
		Subject:    keystone.UserSubject("alice"),
	})
	if err != nil {
		t.Fatalf("unexpected check error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true")
	}
	if client.LatestZookie() != "zk:tenant1:rev10" {
		t.Errorf("expected tracked zookie zk:tenant1:rev10, got %s", client.LatestZookie())
	}

	// 2. Check denied
	respDenied, err := client.Check(context.Background(), keystone.CheckRequest{
		Object:     keystone.ObjectRef{Type: "document", ID: "secret-doc"},
		Permission: "view",
		Subject:    keystone.UserSubject("mallory"),
	})
	if err != nil {
		t.Fatalf("unexpected check error: %v", err)
	}
	if respDenied.Allowed {
		t.Errorf("expected allowed=false")
	}

	// 3. Write relationship updates zookie
	wResp, err := client.WriteRelationships(context.Background(), keystone.WriteRelationshipsRequest{
		Operations: []keystone.TupleOperation{
			{
				Op: "create",
				Tuple: keystone.Tuple{
					ObjectType:  "document",
					ObjectID:    "new-doc",
					Relation:    "owner",
					SubjectType: "user",
					SubjectID:   "alice",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if wResp.Zookie != "zk:tenant1:rev11" {
		t.Errorf("expected zookie zk:tenant1:rev11, got %s", wResp.Zookie)
	}
	if client.LatestZookie() != "zk:tenant1:rev11" {
		t.Errorf("expected latest client zookie updated to zk:tenant1:rev11, got %s", client.LatestZookie())
	}
}

func TestAuthzClient_ProblemDetailsHandling(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(keystone.ProblemDetails{
			Type:   "https://keystone.auth/errors/unknown-relation",
			Title:  "Unknown Relation",
			Status: 400,
			Detail: "relation 'hacker' does not exist in schema for object 'doc'",
		})
	}))
	defer mockServer.Close()

	client, _ := keystone.NewAuthzClient(mockServer.URL, keystone.StaticTokenSource("tok"),
		keystone.WithAuthzHTTPClient(mockServer.Client()))

	_, err := client.Check(context.Background(), keystone.CheckRequest{
		Object:     keystone.ObjectRef{Type: "doc", ID: "1"},
		Permission: "hacker",
		Subject:    keystone.UserSubject("alice"),
	})
	if err == nil {
		t.Fatalf("expected error from check")
	}

	var prob *keystone.ProblemDetails
	if !errors.As(err, &prob) {
		t.Fatalf("expected error to unmarshal to *keystone.ProblemDetails, got: %T (%v)", err, err)
	}
	if prob.Status != 400 || prob.Title != "Unknown Relation" {
		t.Errorf("unexpected problem details: %+v", prob)
	}
}

// ---------------------------------------------------------------------------
// 5. RequirePermission Middleware Tests (Fail-Closed)
// ---------------------------------------------------------------------------

func TestRequirePermissionMiddleware_FailClosed(t *testing.T) {
	var allowCheck bool
	var returnServerError bool

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if returnServerError {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("fatal db error"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(keystone.CheckResponse{
			Allowed: allowCheck,
		})
	}))
	defer mockServer.Close()

	client, _ := keystone.NewAuthzClient(mockServer.URL, keystone.StaticTokenSource("tok"),
		keystone.WithAuthzHTTPClient(mockServer.Client()))

	extractor := func(r *http.Request) (keystone.ObjectRef, string, *keystone.SubjectRef, error) {
		return keystone.ObjectRef{Type: "doc", ID: "123"}, "edit", nil, nil
	}

	permMW := keystone.RequirePermission(client, extractor)

	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authorized-resource"))
	})

	handler := permMW(protectedHandler)

	// Context with user claims
	ctxWithAlice := keystone.ContextWithClaims(context.Background(), &keystone.Claims{
		Subject: "alice",
	})

	// Scenario 1: Allowed -> 200 OK
	allowCheck = true
	returnServerError = false
	req := httptest.NewRequest(http.MethodGet, "/docs/123", nil).WithContext(ctxWithAlice)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for allowed check, got %d", rec.Code)
	}

	// Scenario 2: Denied -> 403 Forbidden (FAIL CLOSED)
	allowCheck = false
	returnServerError = false
	req = httptest.NewRequest(http.MethodGet, "/docs/123", nil).WithContext(ctxWithAlice)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for denied check, got %d", rec.Code)
	}

	// Scenario 3: Engine Down / 500 error -> 503 Service Unavailable (CRITICAL: NEVER 200)
	allowCheck = false
	returnServerError = true
	req = httptest.NewRequest(http.MethodGet, "/docs/123", nil).WithContext(ctxWithAlice)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("CRITICAL SECURITY FLAW: Authz engine outage did not return 503, got status %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// 6. Client Credentials TokenSource Tests
// ---------------------------------------------------------------------------

func TestClientCredentialsTokenSource_Caching(t *testing.T) {
	var tokenCalls int64

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&tokenCalls, 1)
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "client_credentials" ||
			r.FormValue("client_id") != "my-id" ||
			r.FormValue("client_secret") != "my-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "cached-m2m-token-12345",
			"expires_in":   300,
			"token_type":   "Bearer",
		})
	}))
	defer tokenServer.Close()

	ts := keystone.ClientCredentialsTokenSource(
		tokenServer.URL,
		"my-id",
		"my-secret",
		"authz:check authz:write",
		keystone.WithClientCredentialsHTTPClient(tokenServer.Client()),
	)

	// Call 1: fetches token
	tok1, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("failed to fetch token: %v", err)
	}
	if tok1 != "cached-m2m-token-12345" {
		t.Errorf("unexpected token %s", tok1)
	}
	if atomic.LoadInt64(&tokenCalls) != 1 {
		t.Errorf("expected 1 call to token endpoint, got %d", tokenCalls)
	}

	// Call 2: returned from cache, no network call
	tok2, err := ts.Token(context.Background())
	if err != nil {
		t.Fatalf("failed second token fetch: %v", err)
	}
	if tok2 != tok1 {
		t.Errorf("tokens do not match")
	}
	if atomic.LoadInt64(&tokenCalls) != 1 {
		t.Errorf("expected cache hit with 1 call, got %d", tokenCalls)
	}
}
