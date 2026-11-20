package keystone

import (
	"encoding/json"
	"net/http"
)

// PermissionExtractor inspects an HTTP request and extracts the target object, required permission,
// and optional subject. If subject is nil or has an empty Type, the subject is automatically
// inferred from the authenticated Claims in the request context (user:<sub claims>).
type PermissionExtractor func(r *http.Request) (object ObjectRef, permission string, subject *SubjectRef, err error)

// RequirePermissionOption configures the RequirePermission middleware.
type RequirePermissionOption func(*requirePermissionConfig)

type requirePermissionConfig struct {
	consistency   *Consistency
	deniedHandler func(w http.ResponseWriter, r *http.Request, status int, code, msg string)
}

// WithCheckConsistency specifies the snapshot consistency requirements for the check.
func WithCheckConsistency(c *Consistency) RequirePermissionOption {
	return func(cfg *requirePermissionConfig) {
		cfg.consistency = c
	}
}

// WithCustomDeniedHandler overrides the default denial / error response handler.
func WithCustomDeniedHandler(h func(w http.ResponseWriter, r *http.Request, status int, code, msg string)) RequirePermissionOption {
	return func(cfg *requirePermissionConfig) {
		cfg.deniedHandler = h
	}
}

// RequirePermission returns an HTTP middleware that verifies permissions against the Keystone Authz Engine.
// It fails closed: any permission denial yields 403 Forbidden, and any backend error/timeout yields 503.
func RequirePermission(client *AuthzClient, extractor PermissionExtractor, opts ...RequirePermissionOption) func(http.Handler) http.Handler {
	cfg := &requirePermissionConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	defaultDeniedHandler := func(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   code,
			"message": msg,
		})
	}

	deniedHandler := cfg.deniedHandler
	if deniedHandler == nil {
		deniedHandler = defaultDeniedHandler
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			obj, perm, subj, err := extractor(r)
			if err != nil {
				deniedHandler(w, r, http.StatusBadRequest, "bad_request", err.Error())
				return
			}

			// If subject was not explicitly provided by the extractor, resolve from JWT claims
			var resolvedSubj SubjectRef
			if subj != nil && subj.Type != "" {
				resolvedSubj = *subj
			} else {
				claims, ok := ClaimsFromContext(r.Context())
				if !ok || claims.Subject == "" {
					deniedHandler(w, r, http.StatusUnauthorized, "unauthorized", "unauthenticated subject")
					return
				}
				resolvedSubj = UserSubject(claims.Subject)
			}

			checkReq := CheckRequest{
				Object:      obj,
				Permission:  perm,
				Subject:     resolvedSubj,
				Consistency: cfg.consistency,
			}

			// If consistency is not set on check, use client's latest observed zookie for read-your-writes
			if checkReq.Consistency == nil && client.LatestZookie() != "" {
				checkReq.Consistency = AtLeastAsFresh(client.LatestZookie())
			}

			checkResp, err := client.Check(r.Context(), checkReq)
			if err != nil {
				// FAIL CLOSED: Service outage, network failure, or timeout returns 503 Service Unavailable
				deniedHandler(w, r, http.StatusServiceUnavailable, "service_unavailable", "authorization service unavailable")
				return
			}

			if !checkResp.Allowed {
				// FAIL CLOSED: Permission denied returns 403 Forbidden
				deniedHandler(w, r, http.StatusForbidden, "forbidden", "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
