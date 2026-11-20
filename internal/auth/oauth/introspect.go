package oauth

import (
	"context"
	"crypto/rsa"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/raviteja-core/keystone/internal/auth/keys"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/auth/token"
)

// IntrospectHandler implements RFC 7662 OAuth 2.0 Token Introspection.
type IntrospectHandler struct {
	issuer       string
	store        *store.Store
	keyManager   *keys.Manager
	tokenHandler *TokenHandler
	logger       *slog.Logger
	validator    *token.Validator
}

// NewIntrospectHandler creates a new RFC 7662 IntrospectHandler.
func NewIntrospectHandler(issuer string, s *store.Store, km *keys.Manager, th *TokenHandler, logger *slog.Logger) *IntrospectHandler {
	val := token.NewValidator(issuer, "", func(kid string) (*rsa.PublicKey, error) {
		return km.GetPublicKey(context.Background(), kid)
	})

	return &IntrospectHandler{
		issuer:       issuer,
		store:        s,
		keyManager:   km,
		tokenHandler: th,
		logger:       logger,
		validator:    val,
	}
}

// IntrospectionResponse represents RFC 7662 token introspection claims.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	JTI       string   `json:"jti,omitempty"`
	Audience  []string `json:"aud,omitempty"`
}

// ServeHTTP handles POST /introspect.
func (h *IntrospectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Authenticate client (RFC 7662 §2.1: must authenticate)
	client, err := h.tokenHandler.AuthenticateClient(r)
	if err != nil {
		sendError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return
	}

	if err := r.ParseForm(); err != nil {
		sendError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	tokenStr := strings.TrimSpace(r.Form.Get("token"))
	if tokenStr == "" {
		sendError(w, http.StatusBadRequest, "invalid_request", "token parameter is required")
		return
	}

	_ = r.Form.Get("token_type_hint")

	// 2. Inspect token
	claims, err := h.validator.ValidateAccessToken(tokenStr)
	if err != nil {
		// Inactive, expired, or invalid token -> active: false
		sendJSON(w, http.StatusOK, IntrospectionResponse{Active: false})
		return
	}

	// Ensure caller client can introspect token (or has admin scope)
	if client.ClientID != claims.ClientID && client.ClientType != "confidential" {
		sendJSON(w, http.StatusOK, IntrospectionResponse{Active: false})
		return
	}

	resp := IntrospectionResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		Subject:   claims.Subject,
		TokenType: "at+jwt",
		ExpiresAt: claims.Expiry,
		IssuedAt:  claims.IssuedAt,
		Issuer:    claims.Issuer,
		JTI:       claims.ID,
		Audience:  claims.Audience,
	}

	// Verify expiration
	if time.Now().Unix() > claims.Expiry {
		resp.Active = false
	}

	sendJSON(w, http.StatusOK, resp)
}
