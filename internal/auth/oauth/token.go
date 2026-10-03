package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/raviteja-core/keystone/internal/auth/audit"
	"github.com/raviteja-core/keystone/internal/auth/keys"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/auth/token"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

// TokenConfig holds TTL parameters for token generation.
type TokenConfig struct {
	Issuer         string
	AccessTokenTTL time.Duration
	IDTokenTTL     time.Duration
	RefreshIdleTTL time.Duration
	RefreshAbsTTL  time.Duration
}

// TokenHandler handles POST /token.
type TokenHandler struct {
	cfg         TokenConfig
	store       *store.Store
	keyMgr      *keys.Manager
	auditWriter *audit.Writer
	logger      *slog.Logger
}

// NewTokenHandler creates a TokenHandler.
func NewTokenHandler(cfg TokenConfig, s *store.Store, km *keys.Manager, logger *slog.Logger) *TokenHandler {
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = 10 * time.Minute
	}
	if cfg.IDTokenTTL == 0 {
		cfg.IDTokenTTL = 10 * time.Minute
	}
	if cfg.RefreshIdleTTL == 0 {
		cfg.RefreshIdleTTL = 30 * 24 * time.Hour
	}
	if cfg.RefreshAbsTTL == 0 {
		cfg.RefreshAbsTTL = 90 * 24 * time.Hour
	}
	return &TokenHandler{
		cfg:    cfg,
		store:  s,
		keyMgr: km,
		logger: logger,
	}
}

// SetAuditWriter sets the optional audit writer.
func (h *TokenHandler) SetAuditWriter(aw *audit.Writer) {
	h.auditWriter = aw
}

// TokenResponse represents a successful OAuth 2.0 token response (RFC 6749 §5.1).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ErrorResponse represents an OAuth 2.0 error response (RFC 6749 §5.2).
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

func sendJSON(w http.ResponseWriter, statusCode int, data any) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(data)
}

func sendError(w http.ResponseWriter, statusCode int, errCode, errDesc string) {
	sendJSON(w, statusCode, ErrorResponse{
		Error:            errCode,
		ErrorDescription: errDesc,
	})
}

// AuthenticateClient extracts and validates client credentials.
func (h *TokenHandler) AuthenticateClient(r *http.Request) (*store.Client, error) {
	basicUser, basicPass, hasBasic := r.BasicAuth()
	formClientID := r.FormValue("client_id")
	formSecret := r.FormValue("client_secret")

	// Secret in both header and body is forbidden (Probe AS-15)
	if hasBasic && (formClientID != "" || formSecret != "") {
		return nil, errors.New("client credentials must not be provided in both header and body")
	}

	var clientID, clientSecret string
	if hasBasic {
		clientID = basicUser
		clientSecret = basicPass
	} else {
		clientID = formClientID
		clientSecret = formSecret
	}

	if clientID == "" {
		return nil, errors.New("missing client_id")
	}

	client, err := h.store.GetClientByID(r.Context(), clientID)
	if err != nil {
		return nil, store.ErrNotFound
	}
	if client.DisabledAt != nil {
		return nil, errors.New("client is disabled")
	}

	// Verify client credentials
	if client.ClientType == "confidential" {
		if clientSecret == "" {
			return nil, errors.New("client_secret is required for confidential client")
		}
		secretHash := ids.SHA256Digest([]byte(clientSecret))
		if subtle.ConstantTimeCompare(secretHash, client.ClientSecretHash) != 1 {
			return nil, errors.New("invalid client_secret")
		}
	} else if client.ClientType == "public" {
		// Public client must not have secret
		if clientSecret != "" {
			return nil, errors.New("public clients must not provide client_secret")
		}
	}

	return client, nil
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		sendError(w, http.StatusMethodNotAllowed, "invalid_request", "Method must be POST")
		return
	}

	if err := r.ParseForm(); err != nil {
		sendError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form")
		return
	}

	client, err := h.AuthenticateClient(r)
	if err != nil {
		if strings.Contains(err.Error(), "both header and body") {
			sendError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if _, _, hasBasic := r.BasicAuth(); hasBasic {
			w.Header().Set("WWW-Authenticate", `Basic realm="Keystone"`)
		}
		sendError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}

	grantType := r.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCode(w, r, client)
	case "refresh_token":
		h.handleRefreshToken(w, r, client)
	case "client_credentials":
		h.handleClientCredentials(w, r, client)
	default:
		sendError(w, http.StatusBadRequest, "unsupported_grant_type", fmt.Sprintf("Grant type %q is not supported", grantType))
	}
}

// -------------------------------------------------------------------------
// Grant: authorization_code
// -------------------------------------------------------------------------

func (h *TokenHandler) handleAuthorizationCode(w http.ResponseWriter, r *http.Request, client *store.Client) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" || redirectURI == "" || codeVerifier == "" {
		sendError(w, http.StatusBadRequest, "invalid_request", "code, redirect_uri, and code_verifier are required")
		return
	}

	// Code verifier must be 43-128 chars (RFC 7636 §4.1)
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		sendError(w, http.StatusBadRequest, "invalid_grant", "code_verifier length must be between 43 and 128 characters")
		return
	}

	codeHash := ids.SHA256Digest([]byte(code))

	// Atomic single-use code consumption
	authCode, err := h.store.ConsumeAuthCode(r.Context(), codeHash)
	if err != nil {
		if errors.Is(err, store.ErrCodeAlreadyUsed) {
			// REUSE DETECTED (RFC 6749 §4.1.2 / Probe AS-04): Revoke user's refresh tokens for this client!
			if authCode != nil {
				_ = h.store.RevokeTokensByUserAndClient(r.Context(), authCode.UserID, authCode.ClientID, "code_reuse_detected")
			}
			if h.auditWriter != nil {
				reqID := r.Header.Get("X-Request-ID")
				ip := r.RemoteAddr
				ua := r.UserAgent()
				_, _ = h.auditWriter.Record(r.Context(), audit.Event{
					ActorType: "client",
					ActorID:   &client.ClientID,
					Action:    audit.ActionAuthCodeReuse,
					Outcome:   audit.OutcomeFailure,
					IP:        &ip,
					UserAgent: &ua,
					RequestID: &reqID,
					Metadata: map[string]any{
						"client_id": client.ClientID,
					},
				})
			}
			sendError(w, http.StatusBadRequest, "invalid_grant", "Authorization code already redeemed; token family revoked")
			return
		}
		sendError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired authorization code")
		return
	}

	// Verify redirect_uri matches
	if authCode.RedirectURI != redirectURI {
		sendError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Verify client_id matches
	if authCode.ClientID != client.ClientID {
		sendError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}

	// Verify PKCE: BASE64URL(SHA256(code_verifier)) == authCode.CodeChallenge
	verifierHash := sha256.Sum256([]byte(codeVerifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])
	if subtle.ConstantTimeCompare([]byte(computedChallenge), []byte(authCode.CodeChallenge)) != 1 {
		sendError(w, http.StatusBadRequest, "invalid_grant", "code_verifier does not match code_challenge")
		return
	}

	// Fetch active signing key
	signingKey, err := h.keyMgr.GetActiveKey(r.Context())
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "No active signing key")
		return
	}

	issuer := token.NewIssuer(signingKey)

	// Determine audience
	audiences := client.AllowedAudiences
	if len(audiences) == 0 && client.DefaultAudience != nil {
		audiences = []string{*client.DefaultAudience}
	}
	if len(audiences) == 0 {
		audiences = []string{h.cfg.Issuer}
	}

	// Issue Access Token
	var sessIDStr *string
	if len(authCode.SessionHash) > 0 {
		sid := base64.RawURLEncoding.EncodeToString(authCode.SessionHash)
		sessIDStr = &sid
	}

	atParams := token.AccessTokenParams{
		Issuer:    h.cfg.Issuer,
		Subject:   authCode.UserID.String(),
		Audiences: audiences,
		ClientID:  client.ClientID,
		Scope:     authCode.Scope,
		SessionID: sessIDStr,
		AMR:       authCode.AMR,
		TTL:       h.cfg.AccessTokenTTL,
	}

	accessToken, err := issuer.IssueAccessToken(atParams)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "Failed to issue access token")
		return
	}

	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(h.cfg.AccessTokenTTL.Seconds()),
		Scope:       authCode.Scope,
	}

	// Issue ID Token if openid in scope
	scopes := strings.Fields(authCode.Scope)
	hasOpenID := false
	for _, s := range scopes {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}

	if hasOpenID {
		user, _ := h.store.GetUserByID(r.Context(), authCode.UserID)
		idParams := token.IDTokenParams{
			Issuer:      h.cfg.Issuer,
			Subject:     authCode.UserID.String(),
			ClientID:    client.ClientID,
			AuthTime:    authCode.AuthTime,
			Nonce:       authCode.Nonce,
			AccessToken: accessToken,
			SessionID:   sessIDStr,
			AMR:         authCode.AMR,
			Scope:       authCode.Scope,
			TTL:         h.cfg.IDTokenTTL,
		}
		if user != nil {
			idParams.Email = &user.Email
			idParams.EmailVerified = &user.EmailVerified
			idParams.Username = user.Username
			idParams.DisplayName = user.DisplayName
			idParams.UpdatedAt = &user.UpdatedAt
		}
		idToken, err := issuer.IssueIDToken(idParams)
		if err == nil {
			resp.IDToken = idToken
		}
	}

	// Issue Refresh Token if allowed for client
	allowsRefresh := false
	for _, g := range client.AllowedGrantTypes {
		if g == "refresh_token" {
			allowsRefresh = true
			break
		}
	}

	if allowsRefresh {
		rtRaw, err := ids.RandomBase64URL(32)
		if err == nil {
			rtHash := ids.SHA256Digest([]byte(rtRaw))
			familyID, _ := ids.NewUUIDv7()
			rtID, _ := ids.NewUUIDv7()
			now := time.Now()

			rtRecord := &store.RefreshToken{
				ID:                rtID,
				TokenHash:         rtHash,
				FamilyID:          familyID,
				ClientID:          client.ClientID,
				UserID:            authCode.UserID,
				Scope:             authCode.Scope,
				SessionHash:       authCode.SessionHash,
				IssuedAt:          now,
				ExpiresAt:         now.Add(h.cfg.RefreshIdleTTL),
				AbsoluteExpiresAt: now.Add(h.cfg.RefreshAbsTTL),
			}
			if err := h.store.CreateRefreshToken(r.Context(), rtRecord); err == nil {
				resp.RefreshToken = rtRaw
			}
		}
	}

	if h.auditWriter != nil {
		uidStr := authCode.UserID.String()
		reqID := r.Header.Get("X-Request-ID")
		ip := r.RemoteAddr
		ua := r.UserAgent()
		targetType := "client"
		_, _ = h.auditWriter.Record(r.Context(), audit.Event{
			ActorType:  "user",
			ActorID:    &uidStr,
			Action:     audit.ActionTokenIssued,
			TargetType: &targetType,
			TargetID:   &client.ClientID,
			Outcome:    audit.OutcomeSuccess,
			IP:         &ip,
			UserAgent:  &ua,
			RequestID:  &reqID,
			Metadata: map[string]any{
				"grant_type": "authorization_code",
				"client_id":  client.ClientID,
				"scope":      authCode.Scope,
			},
		})
	}

	sendJSON(w, http.StatusOK, resp)
}

// -------------------------------------------------------------------------
// Grant: client_credentials
// -------------------------------------------------------------------------

func (h *TokenHandler) handleClientCredentials(w http.ResponseWriter, r *http.Request, client *store.Client) {
	// Only confidential clients may use client_credentials (Probe AS-15)
	if client.ClientType != "confidential" {
		sendError(w, http.StatusBadRequest, "unauthorized_client", "client_credentials grant is permitted for confidential clients only")
		return
	}

	// Check if client has client_credentials in allowed_grant_types
	allowsGrant := false
	for _, g := range client.AllowedGrantTypes {
		if g == "client_credentials" {
			allowsGrant = true
			break
		}
	}
	if !allowsGrant {
		sendError(w, http.StatusBadRequest, "unauthorized_client", "Client not authorized for client_credentials grant")
		return
	}

	// Validate requested scopes
	reqScope := r.FormValue("scope")
	grantedScope := reqScope
	if grantedScope == "" {
		grantedScope = strings.Join(client.AllowedScopes, " ")
	} else {
		allowedMap := make(map[string]bool, len(client.AllowedScopes))
		for _, s := range client.AllowedScopes {
			allowedMap[s] = true
		}
		for _, s := range strings.Fields(reqScope) {
			if !allowedMap[s] {
				sendError(w, http.StatusBadRequest, "invalid_scope", fmt.Sprintf("Scope %q not allowed", s))
				return
			}
		}
	}

	signingKey, err := h.keyMgr.GetActiveKey(r.Context())
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "No active signing key")
		return
	}

	audiences := client.AllowedAudiences
	if len(audiences) == 0 && client.DefaultAudience != nil {
		audiences = []string{*client.DefaultAudience}
	}
	if len(audiences) == 0 {
		audiences = []string{h.cfg.Issuer}
	}

	issuer := token.NewIssuer(signingKey)
	accessToken, err := issuer.IssueAccessToken(token.AccessTokenParams{
		Issuer:    h.cfg.Issuer,
		Subject:   client.ClientID, // sub = client_id per §6.4
		Audiences: audiences,
		ClientID:  client.ClientID,
		Scope:     grantedScope,
		TTL:       h.cfg.AccessTokenTTL,
	})
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "Failed to issue access token")
		return
	}

	if h.auditWriter != nil {
		reqID := r.Header.Get("X-Request-ID")
		ip := r.RemoteAddr
		ua := r.UserAgent()
		targetType := "client"
		_, _ = h.auditWriter.Record(r.Context(), audit.Event{
			ActorType:  "client",
			ActorID:    &client.ClientID,
			Action:     audit.ActionTokenIssued,
			TargetType: &targetType,
			TargetID:   &client.ClientID,
			Outcome:    audit.OutcomeSuccess,
			IP:         &ip,
			UserAgent:  &ua,
			RequestID:  &reqID,
			Metadata: map[string]any{
				"grant_type": "client_credentials",
				"client_id":  client.ClientID,
				"scope":      grantedScope,
			},
		})
	}

	// No refresh token, no ID token for client_credentials
	sendJSON(w, http.StatusOK, TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(h.cfg.AccessTokenTTL.Seconds()),
		Scope:       grantedScope,
	})
}

// -------------------------------------------------------------------------
// Grant: refresh_token
// -------------------------------------------------------------------------

func (h *TokenHandler) handleRefreshToken(w http.ResponseWriter, r *http.Request, client *store.Client) {
	rawToken := r.FormValue("refresh_token")
	if rawToken == "" {
		sendError(w, http.StatusBadRequest, "invalid_request", "Missing refresh_token")
		return
	}

	tokenHash := ids.SHA256Digest([]byte(rawToken))

	tx, err := h.store.Pool().Begin(r.Context())
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "Transaction begin failed")
		return
	}
	defer tx.Rollback(r.Context()) //nolint:errcheck

	childRaw, err := ids.RandomBase64URL(32)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "Failed to generate new refresh token")
		return
	}
	childHash := ids.SHA256Digest([]byte(childRaw))
	childID, _ := ids.NewUUIDv7()

	now := time.Now()
	childRecord := &store.RefreshToken{
		ID:                childID,
		TokenHash:         childHash,
		ClientID:          client.ClientID,
		IssuedAt:          now,
		ExpiresAt:         now.Add(h.cfg.RefreshIdleTTL),
		AbsoluteExpiresAt: now.Add(h.cfg.RefreshAbsTTL),
	}

	oldToken, rotErr := h.store.RotateRefreshTokenTx(r.Context(), tx, tokenHash, childRecord)
	if rotErr != nil {
		_ = tx.Commit(r.Context()) // Commit family revocation if reuse detected!
		if h.auditWriter != nil {
			reqID := r.Header.Get("X-Request-ID")
			ip := r.RemoteAddr
			ua := r.UserAgent()
			_, _ = h.auditWriter.Record(r.Context(), audit.Event{
				ActorType: "client",
				ActorID:   &client.ClientID,
				Action:    audit.ActionRefreshTokenReuse,
				Outcome:   audit.OutcomeFailure,
				IP:        &ip,
				UserAgent: &ua,
				RequestID: &reqID,
				Metadata: map[string]any{
					"client_id": client.ClientID,
				},
			})
		}
		sendError(w, http.StatusBadRequest, "invalid_grant", "Invalid or revoked refresh token")
		return
	}

	// Verify token belongs to requesting client (Probe AS-14)
	if oldToken.ClientID != client.ClientID {
		sendError(w, http.StatusBadRequest, "invalid_grant", "Refresh token was issued to a different client")
		return
	}

	// Scope narrowing/widening check (Probe AS-13)
	requestedScope := r.FormValue("scope")
	finalScope := oldToken.Scope
	if requestedScope != "" {
		// Requested scope may narrow but MUST NOT widen
		oldScopes := strings.Fields(oldToken.Scope)
		oldScopeMap := make(map[string]bool, len(oldScopes))
		for _, s := range oldScopes {
			oldScopeMap[s] = true
		}
		for _, s := range strings.Fields(requestedScope) {
			if !oldScopeMap[s] {
				sendError(w, http.StatusBadRequest, "invalid_scope", "Requested scope cannot exceed original refresh token scope")
				return
			}
		}
		finalScope = requestedScope
	}

	childRecord.UserID = oldToken.UserID
	childRecord.Scope = finalScope
	childRecord.SessionHash = oldToken.SessionHash

	if err := tx.Commit(r.Context()); err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "Transaction commit failed")
		return
	}

	signingKey, err := h.keyMgr.GetActiveKey(r.Context())
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "No active signing key")
		return
	}

	audiences := client.AllowedAudiences
	if len(audiences) == 0 && client.DefaultAudience != nil {
		audiences = []string{*client.DefaultAudience}
	}
	if len(audiences) == 0 {
		audiences = []string{h.cfg.Issuer}
	}

	var sessIDStr *string
	if len(oldToken.SessionHash) > 0 {
		sid := base64.RawURLEncoding.EncodeToString(oldToken.SessionHash)
		sessIDStr = &sid
	}

	issuer := token.NewIssuer(signingKey)
	accessToken, err := issuer.IssueAccessToken(token.AccessTokenParams{
		Issuer:    h.cfg.Issuer,
		Subject:   oldToken.UserID.String(),
		Audiences: audiences,
		ClientID:  client.ClientID,
		Scope:     finalScope,
		SessionID: sessIDStr,
		TTL:       h.cfg.AccessTokenTTL,
	})
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "Failed to issue access token")
		return
	}

	if h.auditWriter != nil {
		uidStr := oldToken.UserID.String()
		reqID := r.Header.Get("X-Request-ID")
		ip := r.RemoteAddr
		ua := r.UserAgent()
		targetType := "client"
		_, _ = h.auditWriter.Record(r.Context(), audit.Event{
			ActorType:  "user",
			ActorID:    &uidStr,
			Action:     audit.ActionTokenIssued,
			TargetType: &targetType,
			TargetID:   &client.ClientID,
			Outcome:    audit.OutcomeSuccess,
			IP:         &ip,
			UserAgent:  &ua,
			RequestID:  &reqID,
			Metadata: map[string]any{
				"grant_type": "refresh_token",
				"client_id":  client.ClientID,
				"scope":      finalScope,
			},
		})
	}

	sendJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(h.cfg.AccessTokenTTL.Seconds()),
		RefreshToken: childRaw,
		Scope:        finalScope,
	})
}
