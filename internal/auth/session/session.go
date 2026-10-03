package session

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

var (
	ErrNoSession      = errors.New("no active session")
	ErrSessionExpired = errors.New("session expired")
	ErrInvalidCSRF    = errors.New("invalid or missing CSRF token")
)

// Config holds session configuration.
type Config struct {
	CookieSecure bool
	IdleTTL      time.Duration
	AbsoluteTTL  time.Duration
}

// Manager manages user sessions and CSRF tokens.
type Manager struct {
	store *store.Store
	cfg   Config
}

// NewManager creates a session Manager.
func NewManager(s *store.Store, cfg Config) *Manager {
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = 30 * time.Minute
	}
	if cfg.AbsoluteTTL == 0 {
		cfg.AbsoluteTTL = 12 * time.Hour
	}
	return &Manager{
		store: s,
		cfg:   cfg,
	}
}

// SessionCookieName returns the appropriate cookie name based on secure flag.
func (m *Manager) SessionCookieName() string {
	if m.cfg.CookieSecure {
		return "__Host-keystone_session"
	}
	return "keystone_session"
}

// CSRFCookieName returns the CSRF cookie name.
func (m *Manager) CSRFCookieName() string {
	if m.cfg.CookieSecure {
		return "__Host-keystone_csrf"
	}
	return "keystone_csrf"
}

// CreateSession generates a new 32-byte random session ID, stores its SHA-256 hash, and sets the cookie.
func (m *Manager) CreateSession(w http.ResponseWriter, r *http.Request, userID uuid.UUID, amr []string) (string, *store.Session, error) {
	sessionID, err := ids.RandomBase64URL(32)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate session id: %w", err)
	}

	idHash := ids.SHA256Digest([]byte(sessionID))
	now := time.Now()

	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ipStr = r.RemoteAddr
	}
	var ip *string
	if ipStr != "" {
		ip = &ipStr
	}
	userAgent := r.UserAgent()

	sess := &store.Session{
		IDHash:     idHash,
		UserID:     userID,
		AuthTime:   now,
		AMR:        amr,
		IP:         ip,
		UserAgent:  &userAgent,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(m.cfg.IdleTTL),
	}

	if err := m.store.CreateSession(r.Context(), sess); err != nil {
		return "", nil, fmt.Errorf("failed to persist session: %w", err)
	}

	m.SetSessionCookie(w, sessionID)
	return sessionID, sess, nil
}

// RegenerateSession regenerates a session ID upon login (session fixation defense).
func (m *Manager) RegenerateSession(w http.ResponseWriter, r *http.Request, oldSessionID string, userID uuid.UUID, amr []string) (string, *store.Session, error) {
	if oldSessionID != "" {
		oldHash := ids.SHA256Digest([]byte(oldSessionID))
		_ = m.store.RevokeSession(r.Context(), oldHash)
	}
	return m.CreateSession(w, r, userID, amr)
}

// GetSession extracts and validates the active session from request cookies.
func (m *Manager) GetSession(r *http.Request) (*store.Session, error) {
	cookie, err := r.Cookie(m.SessionCookieName())
	if err != nil || cookie.Value == "" {
		return nil, ErrNoSession
	}

	idHash := ids.SHA256Digest([]byte(cookie.Value))
	sess, err := m.store.GetSessionByHash(r.Context(), idHash)
	if err != nil {
		return nil, ErrNoSession
	}

	if sess.RevokedAt != nil {
		return nil, ErrSessionExpired
	}

	now := time.Now()
	// Check idle timeout
	if now.After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}
	// Check absolute timeout
	if now.After(sess.CreatedAt.Add(m.cfg.AbsoluteTTL)) {
		return nil, ErrSessionExpired
	}

	// Update last seen
	_ = m.store.UpdateSessionLastSeen(r.Context(), idHash)

	return sess, nil
}

// SetSessionCookie sets the session cookie with strict security flags.
func (m *Manager) SetSessionCookie(w http.ResponseWriter, sessionID string) {
	cookie := &http.Cookie{
		Name:     m.SessionCookieName(),
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(m.cfg.AbsoluteTTL.Seconds()),
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie clears the session cookie.
func (m *Manager) ClearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     m.SessionCookieName(),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)
}

// EnsureCSRFToken gets existing or issues new CSRF token cookie and returns the token string.
func (m *Manager) EnsureCSRFToken(w http.ResponseWriter, r *http.Request) (string, error) {
	cookie, err := r.Cookie(m.CSRFCookieName())
	if err == nil && len(cookie.Value) >= 32 {
		return cookie.Value, nil
	}

	token, err := ids.RandomBase64URL(32)
	if err != nil {
		return "", err
	}

	csrfCookie := &http.Cookie{
		Name:     m.CSRFCookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600 * 24,
	}
	http.SetCookie(w, csrfCookie)
	return token, nil
}

// ValidateCSRF compares form or header CSRF token with CSRF cookie using constant-time comparison.
func (m *Manager) ValidateCSRF(r *http.Request) error {
	cookie, err := r.Cookie(m.CSRFCookieName())
	if err != nil || cookie.Value == "" {
		return ErrInvalidCSRF
	}

	var submittedToken string
	if r.Header.Get("X-CSRF-Token") != "" {
		submittedToken = r.Header.Get("X-CSRF-Token")
	} else {
		submittedToken = r.FormValue("csrf_token")
	}

	if submittedToken == "" {
		return ErrInvalidCSRF
	}

	if !ids.ConstantTimeStringCompare(cookie.Value, submittedToken) {
		return ErrInvalidCSRF
	}

	return nil
}
