package userinfo

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/auth/token"
)

// Handler handles GET and POST /userinfo.
type Handler struct {
	validator *token.Validator
	store     *store.Store
}

// NewHandler creates a UserInfo Handler.
func NewHandler(v *token.Validator, s *store.Store) *Handler {
	return &Handler{
		validator: v,
		store:     s,
	}
}

// UserInfoResponse represents OIDC UserInfo response claims.
type UserInfoResponse struct {
	Subject           string `json:"sub"`
	Email             string `json:"email,omitempty"`
	EmailVerified     *bool  `json:"email_verified,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Name              string `json:"name,omitempty"`
	UpdatedAt         int64  `json:"updated_at,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Missing bearer token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawToken := strings.TrimPrefix(authHeader, "Bearer ")

	claims, err := h.validator.ValidateAccessToken(rawToken)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Invalid access token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Scope must contain 'openid' (Probe AS-35)
	scopes := strings.Fields(claims.Scope)
	hasOpenID := false
	hasEmail := false
	hasProfile := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
		} else if s == "email" {
			hasEmail = true
		} else if s == "profile" {
			hasProfile = true
		}
	}

	if !hasOpenID {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="openid"`)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	userUUID, err := uuid.Parse(claims.Subject)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	user, err := h.store.GetUserByID(r.Context(), userUUID)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	resp := UserInfoResponse{
		Subject: claims.Subject,
	}

	if hasEmail {
		resp.Email = user.Email
		resp.EmailVerified = &user.EmailVerified
	}
	if hasProfile {
		if user.Username != nil {
			resp.PreferredUsername = *user.Username
		}
		if user.DisplayName != nil {
			resp.Name = *user.DisplayName
		}
		resp.UpdatedAt = user.UpdatedAt.Unix()
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
