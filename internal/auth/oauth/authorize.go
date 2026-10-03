package oauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/raviteja-core/keystone/internal/auth/session"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/auth/ui"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

// AuthorizeHandler handles GET /authorize.
type AuthorizeHandler struct {
	issuer     string
	store      *store.Store
	sessionMgr *session.Manager
	codeTTL    time.Duration
	logger     *slog.Logger
}

// NewAuthorizeHandler creates an AuthorizeHandler.
func NewAuthorizeHandler(issuer string, s *store.Store, sm *session.Manager, codeTTL time.Duration, logger *slog.Logger) *AuthorizeHandler {
	if codeTTL == 0 {
		codeTTL = 60 * time.Second
	}
	return &AuthorizeHandler{
		issuer:     issuer,
		store:      s,
		sessionMgr: sm,
		codeTTL:    codeTTL,
		logger:     logger,
	}
}

// redirectError redirects the user agent to redirect_uri with error parameters (RFC 6749 §4.1.2.1 + RFC 9207 iss).
func (h *AuthorizeHandler) redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		ui.RenderErrorPage(w, http.StatusBadRequest, "Invalid redirect_uri")
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	if errDesc != "" {
		q.Set("error_description", errDesc)
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", h.issuer)
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		ui.RenderErrorPage(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		return
	}

	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	prompt := q.Get("prompt")
	nonce := q.Get("nonce")

	// 1. Look up client_id. Unknown/disabled -> error page. DO NOT REDIRECT (Probe AS-07)
	if clientID == "" {
		ui.RenderErrorPage(w, http.StatusBadRequest, "Missing client_id")
		return
	}
	client, err := h.store.GetClientByID(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			ui.RenderErrorPage(w, http.StatusBadRequest, "Unknown client_id")
			return
		}
		ui.RenderErrorPage(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}
	if client.DisabledAt != nil {
		ui.RenderErrorPage(w, http.StatusBadRequest, "Client is disabled")
		return
	}

	// 2. redirect_uri: MUST exactly string-match one registered URI. Mismatch -> error page. DO NOT REDIRECT (Probe AS-06)
	if redirectURI == "" {
		ui.RenderErrorPage(w, http.StatusBadRequest, "Missing redirect_uri")
		return
	}
	uriMatched := false
	for _, registeredURI := range client.RedirectURIs {
		if redirectURI == registeredURI {
			uriMatched = true
			break
		}
	}
	if !uriMatched {
		ui.RenderErrorPage(w, http.StatusBadRequest, "Invalid redirect_uri")
		return
	}

	// 3. From here on, client_id and redirect_uri are valid: errors may be returned via redirect with state and iss (RFC 9207)

	// 4. response_type: MUST be 'code'. Any other -> unsupported_response_type (Probe AS-08)
	if responseType != "code" {
		h.redirectError(w, r, redirectURI, state, "unsupported_response_type", "Only response_type=code is supported")
		return
	}

	// 5. PKCE: code_challenge is mandatory for ALL clients (Probe AS-01)
	if codeChallenge == "" {
		h.redirectError(w, r, redirectURI, state, "invalid_request", "code_challenge is required for all clients")
		return
	}
	// code_challenge_method MUST be S256 (Probe AS-02)
	if codeChallengeMethod != "S256" {
		h.redirectError(w, r, redirectURI, state, "invalid_request", "code_challenge_method must be S256")
		return
	}
	if len(codeChallenge) != 43 {
		h.redirectError(w, r, redirectURI, state, "invalid_request", "code_challenge must be 43 base64url characters")
		return
	}

	// 6. Scope check: requested scope must be subset of client's allowed scopes (Probe AS-35)
	requestedScopes := strings.Fields(scope)
	if len(requestedScopes) == 0 {
		requestedScopes = []string{"openid"}
	}
	allowedScopeMap := make(map[string]bool, len(client.AllowedScopes))
	for _, s := range client.AllowedScopes {
		allowedScopeMap[s] = true
	}
	for _, s := range requestedScopes {
		if !allowedScopeMap[s] {
			h.redirectError(w, r, redirectURI, state, "invalid_scope", fmt.Sprintf("Scope %q is not allowed for this client", s))
			return
		}
	}

	// 7. Session check
	sess, err := h.sessionMgr.GetSession(r)
	if err != nil || sess == nil || prompt == "login" {
		if prompt == "none" {
			// prompt=none with no active session -> login_required error redirect (Probe AS-38, never render UI)
			h.redirectError(w, r, redirectURI, state, "login_required", "End-user authentication required")
			return
		}
		// Redirect to login form with sanitized relative return_to
		returnURL := r.URL.RequestURI()
		loginRedirect := "/login?return_to=" + url.QueryEscape(returnURL)
		http.Redirect(w, r, loginRedirect, http.StatusFound)
		return
	}

	// 8. Consent check: if client.RequireConsent is true, check stored consent
	if client.RequireConsent && prompt != "none" {
		consent, err := h.store.GetConsent(r.Context(), sess.UserID, client.ClientID)
		needsConsent := false
		if err != nil || consent == nil {
			needsConsent = true
		} else {
			consentedMap := make(map[string]bool)
			for _, s := range strings.Fields(consent.Scope) {
				consentedMap[s] = true
			}
			for _, s := range requestedScopes {
				if !consentedMap[s] {
					needsConsent = true
					break
				}
			}
		}

		if needsConsent {
			returnURL := r.URL.RequestURI()
			consentRedirect := fmt.Sprintf("/consent?client_id=%s&scope=%s&return_to=%s",
				url.QueryEscape(clientID),
				url.QueryEscape(strings.Join(requestedScopes, " ")),
				url.QueryEscape(returnURL))
			http.Redirect(w, r, consentRedirect, http.StatusFound)
			return
		}
	} else if client.RequireConsent && prompt == "none" {
		consent, err := h.store.GetConsent(r.Context(), sess.UserID, client.ClientID)
		if err != nil || consent == nil {
			h.redirectError(w, r, redirectURI, state, "consent_required", "User consent is required")
			return
		}
	}

	// 9. Generate authorization code (32 random bytes base64url, store SHA-256 hash)
	codeRaw, err := ids.RandomBase64URL(32)
	if err != nil {
		h.redirectError(w, r, redirectURI, state, "server_error", "Failed to generate authorization code")
		return
	}
	codeHash := ids.SHA256Digest([]byte(codeRaw))

	var noncePtr *string
	if nonce != "" {
		noncePtr = &nonce
	}

	now := time.Now()
	authCode := &store.AuthorizationCode{
		CodeHash:      codeHash,
		ClientID:      clientID,
		UserID:        sess.UserID,
		RedirectURI:   redirectURI,
		Scope:         strings.Join(requestedScopes, " "),
		Nonce:         noncePtr,
		CodeChallenge: codeChallenge,
		AuthTime:      sess.AuthTime,
		AMR:           sess.AMR,
		SessionHash:   sess.IDHash,
		ExpiresAt:     now.Add(h.codeTTL),
		CreatedAt:     now,
	}

	if err := h.store.CreateAuthCode(r.Context(), authCode); err != nil {
		h.redirectError(w, r, redirectURI, state, "server_error", "Failed to store authorization code")
		return
	}

	// 9. Redirect to redirect_uri with code, state, and iss (RFC 9207, Probe AS-10)
	u, err := url.Parse(redirectURI)
	if err != nil {
		ui.RenderErrorPage(w, http.StatusBadRequest, "Invalid redirect_uri")
		return
	}
	respQuery := u.Query()
	respQuery.Set("code", codeRaw)
	if state != "" {
		respQuery.Set("state", state)
	}
	respQuery.Set("iss", h.issuer)
	u.RawQuery = respQuery.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}
