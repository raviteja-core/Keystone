package oauth

import (
	"crypto/sha256"
	"log/slog"
	"net/http"
	"strings"

	"github.com/raviteja-core/keystone/internal/auth/audit"
	"github.com/raviteja-core/keystone/internal/auth/store"
)

// RevokeHandler implements RFC 7009 OAuth 2.0 Token Revocation.
type RevokeHandler struct {
	store        *store.Store
	tokenHandler *TokenHandler
	logger       *slog.Logger
	auditWriter  *audit.Writer
	revokedJTIs  map[string]bool
}

// NewRevokeHandler creates a new RFC 7009 RevokeHandler.
func NewRevokeHandler(s *store.Store, th *TokenHandler, logger *slog.Logger) *RevokeHandler {
	return &RevokeHandler{
		store:        s,
		tokenHandler: th,
		logger:       logger,
		revokedJTIs:  make(map[string]bool),
	}
}

// SetAuditWriter configures an audit writer for revocation logging.
func (h *RevokeHandler) SetAuditWriter(aw *audit.Writer) {
	h.auditWriter = aw
}

// ServeHTTP handles POST /revoke.
func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Authenticate calling client (RFC 7009 Section 2.1)
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

	// 2. Process revocation
	// Compute SHA-256 hash of token to match stored hashed refresh tokens
	tokenHash := sha256.Sum256([]byte(tokenStr))

	ctx := r.Context()
	if h.store != nil && h.store.Pool() != nil {
		// Attempt refresh token revocation
		_, _ = h.store.Pool().Exec(ctx, `
			UPDATE refresh_tokens 
			SET revoked_at = now(), revoke_reason = 'rfc7009_revocation'
			WHERE token_hash = $1 AND client_id = $2 AND revoked_at IS NULL
		`, tokenHash[:], client.ClientID)
	}

	if h.auditWriter != nil {
		actorID := client.ClientID
		_, _ = h.auditWriter.Record(ctx, audit.Event{
			ActorType: "client",
			ActorID:   &actorID,
			Action:    "token.revoked",
			Outcome:   audit.OutcomeSuccess,
			Metadata: map[string]any{
				"client_id": client.ClientID,
			},
		})
	}

	// RFC 7009 Section 2.2: The authorization server responds with HTTP status code 200
	// if the token has been revoked successfully or if the client submitted an invalid token.
	w.WriteHeader(http.StatusOK)
}

func (h *RevokeHandler) IsJTIRevoked(jti string) bool {
	return h.revokedJTIs[jti]
}
