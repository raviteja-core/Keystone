package api

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/raviteja-core/keystone/internal/auth/token"
	"github.com/raviteja-core/keystone/internal/authz/store"
)

type contextKey string

const (
	tenantCtxKey contextKey = "authz_tenant"
	claimsCtxKey contextKey = "authz_claims"
)

// TenantFromContext extracts the authenticated tenant ID from context.
func TenantFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(tenantCtxKey).(string); ok {
		return val
	}
	return ""
}

// ClaimsFromContext extracts the authenticated token claims from context.
func ClaimsFromContext(ctx context.Context) *AuthTokenClaims {
	if val, ok := ctx.Value(claimsCtxKey).(*AuthTokenClaims); ok {
		return val
	}
	return nil
}

// WithTenantContext returns a context enriched with tenant ID.
func WithTenantContext(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantCtxKey, tenantID)
}

// AuthTokenClaims extends RFC 9068 claims with an optional tenant claim.
type AuthTokenClaims struct {
	token.AccessTokenClaims
	Tenant string `json:"tenant,omitempty"`
}

// JWKSKeyProvider provides RSA public keys given a key ID (kid).
type JWKSKeyProvider interface {
	GetKey(kid string) (*rsa.PublicKey, error)
}

// StaticKeyProvider provides keys from an in-memory map.
type StaticKeyProvider struct {
	keys map[string]*rsa.PublicKey
}

// NewStaticKeyProvider creates a key provider with pre-loaded keys.
func NewStaticKeyProvider(keys map[string]*rsa.PublicKey) *StaticKeyProvider {
	return &StaticKeyProvider{keys: keys}
}

// GetKey returns the RSA public key for the kid.
func (p *StaticKeyProvider) GetKey(kid string) (*rsa.PublicKey, error) {
	k, ok := p.keys[kid]
	if !ok || k == nil {
		return nil, fmt.Errorf("signing key with kid %q not found", kid)
	}
	return k, nil
}

// RemoteJWKSProvider fetches and caches JWKS from a remote URL.
type RemoteJWKSProvider struct {
	url        string
	httpClient *http.Client
	mu         sync.RWMutex
	keys       map[string]*rsa.PublicKey
	lastFetch  time.Time
	cacheTTL   time.Duration
}

// NewRemoteJWKSProvider creates a provider fetching JWKS from an HTTP URL.
func NewRemoteJWKSProvider(jwksURL string, client *http.Client) *RemoteJWKSProvider {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &RemoteJWKSProvider{
		url:        jwksURL,
		httpClient: client,
		keys:       make(map[string]*rsa.PublicKey),
		cacheTTL:   5 * time.Minute,
	}
}

// GetKey looks up the key in cache or fetches from the remote JWKS.
func (p *RemoteJWKSProvider) GetKey(kid string) (*rsa.PublicKey, error) {
	p.mu.RLock()
	k, ok := p.keys[kid]
	fresh := time.Since(p.lastFetch) < p.cacheTTL
	p.mu.RUnlock()

	if ok && fresh {
		return k, nil
	}

	// Refresh cache
	if err := p.refresh(); err != nil {
		if ok {
			return k, nil // return stale on error
		}
		return nil, err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	k, ok = p.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key with kid %q not found in JWKS", kid)
	}
	return k, nil
}

func (p *RemoteJWKSProvider) refresh() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	resp, err := p.httpClient.Get(p.url)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS from %s: %w", p.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if rsaKey, ok := jwk.Key.(*rsa.PublicKey); ok && jwk.KeyID != "" {
			newKeys[jwk.KeyID] = rsaKey
		}
	}

	p.keys = newKeys
	p.lastFetch = time.Now()
	return nil
}

// Authenticator validates Bearer access tokens and enforces scopes.
type Authenticator struct {
	expectedIssuer string
	expectedAud    string
	keyProvider    JWKSKeyProvider
	leeway         time.Duration
}

// NewAuthenticator creates an Authenticator.
func NewAuthenticator(expectedIssuer, expectedAud string, keyProvider JWKSKeyProvider) *Authenticator {
	return &Authenticator{
		expectedIssuer: expectedIssuer,
		expectedAud:    expectedAud,
		keyProvider:    keyProvider,
		leeway:         30 * time.Second,
	}
}

// ValidateToken parses and validates a JWT token string.
func (a *Authenticator) ValidateToken(tokenString string) (*AuthTokenClaims, error) {
	tok, err := jwt.ParseSigned(tokenString, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse JWT (algorithm must be RS256): %v", token.ErrInvalidToken, err)
	}

	if len(tok.Headers) == 0 {
		return nil, fmt.Errorf("%w: missing JOSE header", token.ErrInvalidToken)
	}

	hdr := tok.Headers[0]

	// 1. Enforce RS256 algorithm allowlist strictly
	if hdr.Algorithm != string(jose.RS256) {
		return nil, token.ErrInvalidAlgorithm
	}

	// 2. Enforce typ == at+jwt (RFC 9068)
	typHeader, ok := hdr.ExtraHeaders["typ"].(string)
	if !ok || !strings.EqualFold(typHeader, "at+jwt") {
		return nil, fmt.Errorf("%w: got typ=%q, expected at+jwt", token.ErrInvalidTokenType, typHeader)
	}

	// 3. Look up key by kid
	pubKey, err := a.keyProvider.GetKey(hdr.KeyID)
	if err != nil || pubKey == nil {
		return nil, fmt.Errorf("%w: unknown kid %q", token.ErrSigningKeyNotFound, hdr.KeyID)
	}

	// 4. Verify signature and deserialize claims
	var claims AuthTokenClaims
	if err := tok.Claims(pubKey, &claims); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed: %v", token.ErrInvalidToken, err)
	}

	now := time.Now()

	// 5. Enforce issuer exact match if expectedIssuer configured
	if a.expectedIssuer != "" && claims.Issuer != a.expectedIssuer {
		return nil, fmt.Errorf("%w: got %q, expected %q", token.ErrInvalidIssuer, claims.Issuer, a.expectedIssuer)
	}

	// 6. Enforce audience
	if a.expectedAud != "" {
		audMatched := false
		for _, aud := range claims.Audience {
			if aud == a.expectedAud {
				audMatched = true
				break
			}
		}
		if !audMatched {
			return nil, fmt.Errorf("%w: token audiences %v do not include %q", token.ErrInvalidAudience, claims.Audience, a.expectedAud)
		}
	}

	// 7. Enforce expiration with leeway
	expTime := time.Unix(claims.Expiry, 0)
	if now.After(expTime.Add(a.leeway)) {
		return nil, token.ErrTokenExpired
	}

	// Enforce nbf with leeway
	if claims.NotBefore > 0 {
		nbfTime := time.Unix(claims.NotBefore, 0)
		if now.Before(nbfTime.Add(-a.leeway)) {
			return nil, fmt.Errorf("%w: token not yet valid", token.ErrInvalidToken)
		}
	}

	return &claims, nil
}

// RequireScope returns an HTTP middleware enforcing that requests have a valid Bearer token with requiredScope.
func (a *Authenticator) RequireScope(requiredScope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing Authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "malformed Authorization header, expected Bearer <token>")
				return
			}

			tokenStr := strings.TrimSpace(parts[1])
			claims, err := a.ValidateToken(tokenStr)
			if err != nil {
				WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", err.Error())
				return
			}

			// Scope verification
			if !HasScope(claims.Scope, requiredScope) {
				WriteProblem(w, r, http.StatusForbidden, "Forbidden", fmt.Sprintf("insufficient scope: requires %q", requiredScope))
				return
			}

			// Tenant extraction: claim 'tenant', else 'client_id'
			tenantID := claims.Tenant
			if tenantID == "" {
				tenantID = claims.ClientID
			}
			if tenantID == "" {
				tenantID = claims.Subject
			}

			if !store.ValidateID(tenantID, false) {
				WriteProblem(w, r, http.StatusBadRequest, "Invalid Tenant", fmt.Sprintf("invalid tenant identifier %q", tenantID))
				return
			}

			ctx := context.WithValue(r.Context(), tenantCtxKey, tenantID)
			ctx = context.WithValue(ctx, claimsCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
