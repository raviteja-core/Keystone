package ui

import (
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/raviteja-core/keystone/internal/auth/audit"
	"github.com/raviteja-core/keystone/internal/auth/password"
	"github.com/raviteja-core/keystone/internal/auth/session"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/auth/ui/templates"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

// Security headers applied to all HTML UI responses
func setUIHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
}

// ValidateReturnTo strictly enforces that return_to is a relative path starting with /authorize.
func ValidateReturnTo(returnTo string) string {
	if returnTo == "" {
		return "/"
	}
	// Must start with /authorize
	if !strings.HasPrefix(returnTo, "/authorize") {
		return "/"
	}
	// Reject protocol-relative and backslash escapes
	if strings.HasPrefix(returnTo, "//") || strings.HasPrefix(returnTo, "/\\") {
		return "/"
	}
	// Check for authority injection via @
	if strings.Contains(returnTo, "@") {
		return "/"
	}
	// Reject whitespace and control chars
	for _, r := range returnTo {
		if r <= ' ' || r == 127 {
			return "/"
		}
	}
	parsed, err := url.Parse(returnTo)
	if err != nil || parsed.Host != "" || parsed.Scheme != "" {
		return "/"
	}
	if !strings.HasPrefix(parsed.Path, "/authorize") {
		return "/"
	}
	return returnTo
}

var (
	parsedTemplates = template.Must(template.ParseFS(templates.FS, "*.html"))
	loginTmpl       = parsedTemplates.Lookup("login.html")
	registerTmpl    = parsedTemplates.Lookup("register.html")
	consentTmpl     = parsedTemplates.Lookup("consent.html")
	errorTmpl       = parsedTemplates.Lookup("error.html")
)

// ScopeItem represents a scope displayed on the consent screen.
type ScopeItem struct {
	Name        string
	Description string
}

// Handler coordinates UI routes.
type Handler struct {
	store       *store.Store
	session     *session.Manager
	hasher      *password.Hasher
	auditWriter *audit.Writer
	logger      *slog.Logger
}

// NewHandler creates a UI handler.
func NewHandler(s *store.Store, sm *session.Manager, h *password.Hasher, aw *audit.Writer, logger *slog.Logger) *Handler {
	return &Handler{
		store:       s,
		session:     sm,
		hasher:      h,
		auditWriter: aw,
		logger:      logger,
	}
}

// RenderErrorPage renders a generic security error page (used when redirect_uri is invalid or client unknown).
func RenderErrorPage(w http.ResponseWriter, statusCode int, message string) {
	setUIHeaders(w)
	w.WriteHeader(statusCode)
	_ = errorTmpl.Execute(w, map[string]string{
		"Message": message,
	})
}

// HandleLogin renders GET /login or processes POST /login.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	setUIHeaders(w)

	switch r.Method {
	case http.MethodGet:
		csrfToken, err := h.session.EnsureCSRFToken(w, r)
		if err != nil {
			RenderErrorPage(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		returnTo := ValidateReturnTo(r.URL.Query().Get("return_to"))
		_ = loginTmpl.Execute(w, map[string]string{
			"CSRFToken": csrfToken,
			"ReturnTo":  returnTo,
			"Email":     r.URL.Query().Get("login_hint"),
			"Error":     "",
		})

	case http.MethodPost:
		// 1. Enforce CSRF
		if err := h.session.ValidateCSRF(r); err != nil {
			RenderErrorPage(w, http.StatusForbidden, "Invalid or missing CSRF token")
			return
		}

		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		plainPassword := r.FormValue("password")
		rawReturnTo := r.FormValue("return_to")
		returnTo := ValidateReturnTo(rawReturnTo)

		csrfToken, _ := h.session.EnsureCSRFToken(w, r)

		if email == "" || plainPassword == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = loginTmpl.Execute(w, map[string]string{
				"CSRFToken": csrfToken,
				"ReturnTo":  returnTo,
				"Email":     email,
				"Error":     "Invalid email or password",
			})
			return
		}

		user, err := h.store.GetUserByEmail(r.Context(), email)
		if err != nil {
			// User not found: run dummy hash verification to preserve constant-time execution against enumeration (AS-22)
			h.hasher.VerifyDummy(plainPassword)

			if h.auditWriter != nil {
				reqID := r.Header.Get("X-Request-ID")
				ip := r.RemoteAddr
				ua := r.UserAgent()
				actType := "anonymous"
				_, _ = h.auditWriter.Record(r.Context(), audit.Event{
					ActorType: "anonymous",
					Action:    audit.ActionAuthLoginFailed,
					Outcome:   audit.OutcomeFailure,
					IP:        &ip,
					UserAgent: &ua,
					RequestID: &reqID,
					Metadata: map[string]any{
						"attempted_email": email,
					},
				})
				_ = actType
			}

			w.WriteHeader(http.StatusUnauthorized)
			_ = loginTmpl.Execute(w, map[string]string{
				"CSRFToken": csrfToken,
				"ReturnTo":  returnTo,
				"Email":     "",
				"Error":     "Invalid email or password",
			})
			return
		}

		// Verify password
		valid, needsRehash, err := h.hasher.Verify(plainPassword, user.PasswordHash)
		if err != nil || !valid {
			_ = h.store.IncrementFailedLogin(r.Context(), user.ID, nil)

			if h.auditWriter != nil {
				reqID := r.Header.Get("X-Request-ID")
				ip := r.RemoteAddr
				ua := r.UserAgent()
				uidStr := user.ID.String()
				_, _ = h.auditWriter.Record(r.Context(), audit.Event{
					ActorType: "user",
					ActorID:   &uidStr,
					Action:    audit.ActionAuthLoginFailed,
					Outcome:   audit.OutcomeFailure,
					IP:        &ip,
					UserAgent: &ua,
					RequestID: &reqID,
					Metadata: map[string]any{
						"email": email,
					},
				})
			}

			w.WriteHeader(http.StatusUnauthorized)
			_ = loginTmpl.Execute(w, map[string]string{
				"CSRFToken": csrfToken,
				"ReturnTo":  returnTo,
				"Email":     "",
				"Error":     "Invalid email or password",
			})
			return
		}

		// Rehash if parameters changed
		if needsRehash {
			if newHash, hashErr := h.hasher.Hash(plainPassword); hashErr == nil {
				_ = h.store.UpdateUserPassword(r.Context(), user.ID, newHash)
			}
		}

		// Reset failed login count
		_ = h.store.ResetFailedLogin(r.Context(), user.ID)

		// Regenerate session (fixation defense)
		oldCookie, _ := r.Cookie(h.session.SessionCookieName())
		oldSessID := ""
		if oldCookie != nil {
			oldSessID = oldCookie.Value
		}

		_, _, err = h.session.RegenerateSession(w, r, oldSessID, user.ID, []string{"pwd"})
		if err != nil {
			RenderErrorPage(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		if h.auditWriter != nil {
			reqID := r.Header.Get("X-Request-ID")
			ip := r.RemoteAddr
			ua := r.UserAgent()
			uidStr := user.ID.String()
			_, _ = h.auditWriter.Record(r.Context(), audit.Event{
				ActorType: "user",
				ActorID:   &uidStr,
				Action:    audit.ActionAuthLoginSucceeded,
				Outcome:   audit.OutcomeSuccess,
				IP:        &ip,
				UserAgent: &ua,
				RequestID: &reqID,
				Metadata: map[string]any{
					"email": email,
				},
			})
		}

		// Redirect to return_to
		http.Redirect(w, r, returnTo, http.StatusFound)

	default:
		RenderErrorPage(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

// HandleRegister renders GET /register or processes POST /register.
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	setUIHeaders(w)

	switch r.Method {
	case http.MethodGet:
		csrfToken, err := h.session.EnsureCSRFToken(w, r)
		if err != nil {
			RenderErrorPage(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		returnTo := ValidateReturnTo(r.URL.Query().Get("return_to"))
		_ = registerTmpl.Execute(w, map[string]string{
			"CSRFToken": csrfToken,
			"ReturnTo":  returnTo,
			"Email":     "",
			"Username":  "",
			"Error":     "",
		})

	case http.MethodPost:
		// 1. Enforce CSRF
		if err := h.session.ValidateCSRF(r); err != nil {
			RenderErrorPage(w, http.StatusForbidden, "Invalid or missing CSRF token")
			return
		}

		email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
		plainPassword := r.FormValue("password")
		username := strings.TrimSpace(r.FormValue("username"))
		returnTo := ValidateReturnTo(r.FormValue("return_to"))

		csrfToken, _ := h.session.EnsureCSRFToken(w, r)

		if email == "" || !strings.Contains(email, "@") {
			w.WriteHeader(http.StatusBadRequest)
			_ = registerTmpl.Execute(w, map[string]string{
				"CSRFToken": csrfToken,
				"ReturnTo":  returnTo,
				"Email":     email,
				"Username":  username,
				"Error":     "Valid email address is required",
			})
			return
		}

		// Validate password policy
		if _, err := password.ValidatePolicy(plainPassword); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = registerTmpl.Execute(w, map[string]string{
				"CSRFToken": csrfToken,
				"ReturnTo":  returnTo,
				"Email":     email,
				"Username":  username,
				"Error":     err.Error(),
			})
			return
		}

		// Hash password
		hash, err := h.hasher.Hash(plainPassword)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = registerTmpl.Execute(w, map[string]string{
				"CSRFToken": csrfToken,
				"ReturnTo":  returnTo,
				"Email":     email,
				"Username":  username,
				"Error":     fmt.Sprintf("Password error: %v", err),
			})
			return
		}

		uid, err := ids.NewUUIDv7()
		if err != nil {
			uid = uuid.New()
		}

		var unamePtr *string
		if username != "" {
			unamePtr = &username
		}

		user := &store.User{
			ID:            uid,
			Email:         email,
			Username:      unamePtr,
			PasswordHash:  hash,
			Status:        "active",
			EmailVerified: false,
		}

		if err := h.store.CreateUser(r.Context(), user); err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				w.WriteHeader(http.StatusConflict)
				_ = registerTmpl.Execute(w, map[string]string{
					"CSRFToken": csrfToken,
					"ReturnTo":  returnTo,
					"Email":     email,
					"Username":  username,
					"Error":     "Email or username already registered",
				})
				return
			}
			RenderErrorPage(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		if h.auditWriter != nil {
			reqID := r.Header.Get("X-Request-ID")
			ip := r.RemoteAddr
			ua := r.UserAgent()
			uidStr := user.ID.String()
			_, _ = h.auditWriter.Record(r.Context(), audit.Event{
				ActorType: "user",
				ActorID:   &uidStr,
				Action:    audit.ActionUserRegistered,
				Outcome:   audit.OutcomeSuccess,
				IP:        &ip,
				UserAgent: &ua,
				RequestID: &reqID,
				Metadata: map[string]any{
					"email": email,
				},
			})
		}

		// Create session and log user in immediately
		_, _, err = h.session.CreateSession(w, r, user.ID, []string{"pwd"})
		if err != nil {
			RenderErrorPage(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		http.Redirect(w, r, returnTo, http.StatusFound)

	default:
		RenderErrorPage(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

// HandleConsent renders GET /consent or processes POST /consent.
func (h *Handler) HandleConsent(w http.ResponseWriter, r *http.Request) {
	setUIHeaders(w)

	// User must have an active session
	sess, err := h.session.GetSession(r)
	if err != nil || sess == nil {
		loginURL := "/login?return_to=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		clientID := r.URL.Query().Get("client_id")
		scope := r.URL.Query().Get("scope")
		returnTo := ValidateReturnTo(r.URL.Query().Get("return_to"))

		client, err := h.store.GetClientByID(r.Context(), clientID)
		if err != nil || client == nil {
			RenderErrorPage(w, http.StatusBadRequest, "Invalid client_id")
			return
		}

		csrfToken, err := h.session.EnsureCSRFToken(w, r)
		if err != nil {
			RenderErrorPage(w, http.StatusInternalServerError, "Internal Server Error")
			return
		}

		scopes := formatScopes(scope)
		_ = consentTmpl.Execute(w, map[string]any{
			"ClientName": client.Name,
			"ClientID":   clientID,
			"Scope":      scope,
			"Scopes":     scopes,
			"CSRFToken":  csrfToken,
			"ReturnTo":   returnTo,
			"Error":      "",
		})

	case http.MethodPost:
		if err := h.session.ValidateCSRF(r); err != nil {
			RenderErrorPage(w, http.StatusForbidden, "Invalid or missing CSRF token")
			return
		}

		clientID := r.FormValue("client_id")
		scope := r.FormValue("scope")
		rawReturnTo := r.FormValue("return_to")
		returnTo := ValidateReturnTo(rawReturnTo)
		action := r.FormValue("action")

		client, err := h.store.GetClientByID(r.Context(), clientID)
		if err != nil || client == nil {
			RenderErrorPage(w, http.StatusBadRequest, "Invalid client_id")
			return
		}

		if action == "deny" {
			// Redirect back to client callback with access_denied
			parsedReturn, err := url.Parse(returnTo)
			if err != nil {
				RenderErrorPage(w, http.StatusBadRequest, "Invalid return_to")
				return
			}
			redirectURI := parsedReturn.Query().Get("redirect_uri")
			state := parsedReturn.Query().Get("state")
			if redirectURI == "" {
				redirectURI = client.RedirectURIs[0]
			}
			u, _ := url.Parse(redirectURI)
			q := u.Query()
			q.Set("error", "access_denied")
			q.Set("error_description", "User denied authorization")
			if state != "" {
				q.Set("state", state)
			}
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}

		// User accepted: persist consent
		consent := &store.Consent{
			UserID:    sess.UserID,
			ClientID:  clientID,
			Scope:     scope,
			GrantedAt: time.Now(),
		}
		if err := h.store.SaveConsent(r.Context(), consent); err != nil {
			RenderErrorPage(w, http.StatusInternalServerError, "Failed to save consent")
			return
		}

		// Redirect back to return_to (/authorize)
		http.Redirect(w, r, returnTo, http.StatusFound)

	default:
		RenderErrorPage(w, http.StatusMethodNotAllowed, "Method Not Allowed")
	}
}

// formatScopes converts scope strings to human-readable labels.
func formatScopes(scopeStr string) []ScopeItem {
	scopeMap := map[string]string{
		"openid":         "Verify your identity (OpenID Connect)",
		"profile":        "Access your profile information (name, username)",
		"email":          "Access your email address",
		"offline_access": "Access your account in the background (refresh tokens)",
	}

	var items []ScopeItem
	for _, s := range strings.Fields(scopeStr) {
		desc, ok := scopeMap[s]
		if !ok {
			desc = "Access " + s + " permissions"
		}
		items = append(items, ScopeItem{Name: s, Description: desc})
	}
	return items
}
