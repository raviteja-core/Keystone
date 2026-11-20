package keystone

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// MiddlewareOption configures the authentication middleware.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	requiredScope string
	errorHandler  func(w http.ResponseWriter, r *http.Request, status int, errCode, errDesc string)
}

// WithRequiredScope configures the middleware to reject requests whose token lacks the specified scope.
func WithRequiredScope(scope string) MiddlewareOption {
	return func(c *middlewareConfig) {
		c.requiredScope = scope
	}
}

// WithCustomErrorHandler configures a custom HTTP error handler.
func WithCustomErrorHandler(h func(w http.ResponseWriter, r *http.Request, status int, errCode, errDesc string)) MiddlewareOption {
	return func(c *middlewareConfig) {
		c.errorHandler = h
	}
}

// Middleware creates a standard net/http middleware that authenticates requests using RFC 9068 Bearer JWTs.
func Middleware(verifier *Verifier, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	cfg := &middlewareConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	defaultErrorHandler := func(w http.ResponseWriter, r *http.Request, status int, errCode, errDesc string) {
		w.Header().Set("Content-Type", "application/json")
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, errCode, errDesc))
		} else if status == http.StatusForbidden {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", scope="%s"`, errCode, cfg.requiredScope))
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             errCode,
			"error_description": errDesc,
		})
	}

	errHandler := cfg.errorHandler
	if errHandler == nil {
		errHandler = defaultErrorHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHdr := r.Header.Get("Authorization")
			if authHdr == "" {
				errHandler(w, r, http.StatusUnauthorized, "invalid_token", "missing Authorization header")
				return
			}

			parts := strings.SplitN(authHdr, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				errHandler(w, r, http.StatusUnauthorized, "invalid_token", "malformed Authorization header, expected 'Bearer <token>'")
				return
			}

			rawToken := strings.TrimSpace(parts[1])
			if rawToken == "" {
				errHandler(w, r, http.StatusUnauthorized, "invalid_token", "empty bearer token")
				return
			}

			claims, err := verifier.Verify(r.Context(), rawToken)
			if err != nil {
				errHandler(w, r, http.StatusUnauthorized, "invalid_token", err.Error())
				return
			}

			if cfg.requiredScope != "" && !claims.HasScope(cfg.requiredScope) {
				errHandler(w, r, http.StatusForbidden, "insufficient_scope", fmt.Sprintf("token missing required scope %q", cfg.requiredScope))
				return
			}

			ctx := ContextWithClaims(r.Context(), claims)
			ctx = ContextWithRawToken(ctx, rawToken)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
