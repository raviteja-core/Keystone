package keystone

import (
	"context"
	"strings"
	"time"
)

type contextKey string

const (
	claimsContextKey = contextKey("keystone.claims")
	rawTokenKey      = contextKey("keystone.raw_token")
)

// Claims represents validated RFC 9068 JWT access token claims.
type Claims struct {
	Subject   string                 `json:"sub"`
	Issuer    string                 `json:"iss"`
	Audiences []string               `json:"aud"`
	ClientID  string                 `json:"client_id"`
	Scope     string                 `json:"scope"`
	JTI       string                 `json:"jti"`
	IssuedAt  time.Time              `json:"iat"`
	ExpiresAt time.Time              `json:"exp"`
	NotBefore *time.Time             `json:"nbf,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

// HasScope checks whether the claims contain the required scope.
func (c *Claims) HasScope(requiredScope string) bool {
	if c == nil || c.Scope == "" {
		return false
	}
	fields := strings.Fields(c.Scope)
	for _, s := range fields {
		if s == requiredScope {
			return true
		}
	}
	return false
}

// ContextWithClaims returns a new Context that carries the validated Claims.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// ClaimsFromContext extracts the Claims from the context if present.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsContextKey).(*Claims)
	return c, ok && c != nil
}

// SubjectFromContext extracts the subject (sub) from the context claims if present.
func SubjectFromContext(ctx context.Context) string {
	if c, ok := ClaimsFromContext(ctx); ok {
		return c.Subject
	}
	return ""
}

// ContextWithRawToken returns a new Context that carries the raw Bearer token string.
func ContextWithRawToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, rawTokenKey, token)
}

// RawTokenFromContext extracts the raw Bearer token from the context if present.
func RawTokenFromContext(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(rawTokenKey).(string)
	return t, ok && t != ""
}
