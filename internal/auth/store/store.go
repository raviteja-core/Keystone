package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound        = errors.New("record not found")
	ErrAlreadyExists   = errors.New("record already exists")
	ErrCodeAlreadyUsed = errors.New("authorization code already used")
	ErrCodeExpired     = errors.New("authorization code expired")
)

// User represents a user record in the auth DB.
type User struct {
	ID               uuid.UUID
	Email            string
	EmailVerified    bool
	Username         *string
	DisplayName      *string
	PasswordHash     string
	Status           string // 'active', 'disabled'
	ExternalID       *string
	MFAEnabled       bool
	FailedLoginCount int
	LockedUntil      *time.Time
	Version          int
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Client represents an OAuth2 / OIDC client.
type Client struct {
	ID                      uuid.UUID
	ClientID                string
	ClientSecretHash        []byte // SHA-256 hash; nil for public clients
	Name                    string
	ClientType              string // 'public', 'confidential'
	TokenEndpointAuthMethod string // 'none', 'client_secret_basic', 'client_secret_post'
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	AllowedGrantTypes       []string
	AllowedScopes           []string
	AllowedAudiences        []string
	DefaultAudience         *string
	RequireConsent          bool
	AccessTokenTTLSeconds   *int
	CreatedAt               time.Time
	DisabledAt              *time.Time
}

// Session represents an authenticated user web session.
type Session struct {
	IDHash     []byte // SHA-256(session_id)
	UserID     uuid.UUID
	AuthTime   time.Time
	AMR        []string
	IP         *string
	UserAgent  *string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}

// AuthorizationCode represents a single-use OAuth2 authorization code.
type AuthorizationCode struct {
	CodeHash      []byte // SHA-256(code)
	ClientID      string
	UserID        uuid.UUID
	RedirectURI   string
	Scope         string
	Nonce         *string
	CodeChallenge string
	AuthTime      time.Time
	AMR           []string
	SessionHash   []byte
	ExpiresAt     time.Time
	UsedAt        *time.Time
	CreatedAt     time.Time
}

// RefreshToken represents a token in a refresh token rotation family.
type RefreshToken struct {
	ID                uuid.UUID
	TokenHash         []byte // SHA-256(token)
	FamilyID          uuid.UUID
	ParentID          *uuid.UUID
	ClientID          string
	UserID            uuid.UUID
	Scope             string
	SessionHash       []byte
	IssuedAt          time.Time
	ExpiresAt         time.Time
	AbsoluteExpiresAt time.Time
	RotatedAt         *time.Time
	RevokedAt         *time.Time
	RevokedReason     *string
}

// Consent represents a user's consent granted to a client.
type Consent struct {
	UserID    uuid.UUID
	ClientID  string
	Scope     string
	GrantedAt time.Time
}

// Store provides PostgreSQL persistence for auth server domain models.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new Store.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Pool returns the underlying pgxpool.Pool.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}

// -------------------------------------------------------------------------
// User Operations
// -------------------------------------------------------------------------

// CreateUser inserts a new user.
func (s *Store) CreateUser(ctx context.Context, u *User) error {
	now := time.Now()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	if u.UpdatedAt.IsZero() {
		u.UpdatedAt = now
	}
	if u.Status == "" {
		u.Status = "active"
	}
	if u.Version == 0 {
		u.Version = 1
	}

	query := `
		INSERT INTO users (
			id, email, email_verified, username, display_name, password_hash,
			status, external_id, mfa_enabled, failed_login_count, locked_until,
			version, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
	`
	_, err := s.pool.Exec(ctx, query,
		u.ID, u.Email, u.EmailVerified, u.Username, u.DisplayName, u.PasswordHash,
		u.Status, u.ExternalID, u.MFAEnabled, u.FailedLoginCount, u.LockedUntil,
		u.Version, u.CreatedAt, u.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyExists
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetUserByID retrieves a user by UUID.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	query := `
		SELECT id, email, email_verified, username, display_name, password_hash,
		       status, external_id, mfa_enabled, failed_login_count, locked_until,
		       version, created_at, updated_at
		FROM users
		WHERE id = $1
	`
	var u User
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&u.ID, &u.Email, &u.EmailVerified, &u.Username, &u.DisplayName, &u.PasswordHash,
		&u.Status, &u.ExternalID, &u.MFAEnabled, &u.FailedLoginCount, &u.LockedUntil,
		&u.Version, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}
	return &u, nil
}

// GetUserByEmail retrieves a user by case-insensitive email.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, email, email_verified, username, display_name, password_hash,
		       status, external_id, mfa_enabled, failed_login_count, locked_until,
		       version, created_at, updated_at
		FROM users
		WHERE lower(email) = lower($1)
	`
	var u User
	err := s.pool.QueryRow(ctx, query, email).Scan(
		&u.ID, &u.Email, &u.EmailVerified, &u.Username, &u.DisplayName, &u.PasswordHash,
		&u.Status, &u.ExternalID, &u.MFAEnabled, &u.FailedLoginCount, &u.LockedUntil,
		&u.Version, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}
	return &u, nil
}

// UpdateUserPassword updates a user's password hash and version.
func (s *Store) UpdateUserPassword(ctx context.Context, id uuid.UUID, newHash string) error {
	query := `
		UPDATE users
		SET password_hash = $1, version = version + 1, updated_at = now()
		WHERE id = $2
	`
	cmd, err := s.pool.Exec(ctx, query, newHash, id)
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IncrementFailedLogin increments failed_login_count and optionally locks the account until lockedUntil.
func (s *Store) IncrementFailedLogin(ctx context.Context, id uuid.UUID, lockedUntil *time.Time) error {
	query := `
		UPDATE users
		SET failed_login_count = failed_login_count + 1,
		    locked_until = COALESCE($1, locked_until),
		    updated_at = now()
		WHERE id = $2
	`
	cmd, err := s.pool.Exec(ctx, query, lockedUntil, id)
	if err != nil {
		return fmt.Errorf("failed to increment failed login: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ResetFailedLogin resets the failed_login_count and unlocks the account.
func (s *Store) ResetFailedLogin(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET failed_login_count = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1
	`
	cmd, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to reset failed login: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// -------------------------------------------------------------------------
// Client Operations
// -------------------------------------------------------------------------

// CreateClient inserts a new OAuth2 client.
func (s *Store) CreateClient(ctx context.Context, c *Client) error {
	now := time.Now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	if c.PostLogoutRedirectURIs == nil {
		c.PostLogoutRedirectURIs = []string{}
	}
	if c.AllowedGrantTypes == nil {
		c.AllowedGrantTypes = []string{}
	}
	if c.AllowedScopes == nil {
		c.AllowedScopes = []string{}
	}
	if c.AllowedAudiences == nil {
		c.AllowedAudiences = []string{}
	}

	query := `
		INSERT INTO clients (
			id, client_id, client_secret_hash, name, client_type,
			token_endpoint_auth_method, redirect_uris, post_logout_redirect_uris,
			allowed_grant_types, allowed_scopes, allowed_audiences,
			default_audience, require_consent, access_token_ttl_seconds,
			created_at, disabled_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		)
	`
	_, err := s.pool.Exec(ctx, query,
		c.ID, c.ClientID, c.ClientSecretHash, c.Name, c.ClientType,
		c.TokenEndpointAuthMethod, c.RedirectURIs, c.PostLogoutRedirectURIs,
		c.AllowedGrantTypes, c.AllowedScopes, c.AllowedAudiences,
		c.DefaultAudience, c.RequireConsent, c.AccessTokenTTLSeconds,
		c.CreatedAt, c.DisabledAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrAlreadyExists
		}
		return fmt.Errorf("failed to create client: %w", err)
	}
	return nil
}

// GetClientByID retrieves a client by its client_id.
func (s *Store) GetClientByID(ctx context.Context, clientID string) (*Client, error) {
	query := `
		SELECT id, client_id, client_secret_hash, name, client_type,
		       token_endpoint_auth_method, redirect_uris, post_logout_redirect_uris,
		       allowed_grant_types, allowed_scopes, allowed_audiences,
		       default_audience, require_consent, access_token_ttl_seconds,
		       created_at, disabled_at
		FROM clients
		WHERE client_id = $1
	`
	var c Client
	err := s.pool.QueryRow(ctx, query, clientID).Scan(
		&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name, &c.ClientType,
		&c.TokenEndpointAuthMethod, &c.RedirectURIs, &c.PostLogoutRedirectURIs,
		&c.AllowedGrantTypes, &c.AllowedScopes, &c.AllowedAudiences,
		&c.DefaultAudience, &c.RequireConsent, &c.AccessTokenTTLSeconds,
		&c.CreatedAt, &c.DisabledAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get client by id: %w", err)
	}
	return &c, nil
}

// -------------------------------------------------------------------------
// Session Operations
// -------------------------------------------------------------------------

// CreateSession inserts a session row.
func (s *Store) CreateSession(ctx context.Context, sess *Session) error {
	now := time.Now()
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = now
	}
	if sess.LastSeenAt.IsZero() {
		sess.LastSeenAt = now
	}

	query := `
		INSERT INTO sessions (
			id_hash, user_id, auth_time, amr, ip, user_agent,
			created_at, last_seen_at, expires_at, revoked_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
	`
	_, err := s.pool.Exec(ctx, query,
		sess.IDHash, sess.UserID, sess.AuthTime, sess.AMR, sess.IP, sess.UserAgent,
		sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt, sess.RevokedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	return nil
}

// GetSessionByHash retrieves an active session by SHA-256 ID hash.
func (s *Store) GetSessionByHash(ctx context.Context, idHash []byte) (*Session, error) {
	query := `
		SELECT id_hash, user_id, auth_time, amr, host(ip), user_agent,
		       created_at, last_seen_at, expires_at, revoked_at
		FROM sessions
		WHERE id_hash = $1
	`
	var sess Session
	err := s.pool.QueryRow(ctx, query, idHash).Scan(
		&sess.IDHash, &sess.UserID, &sess.AuthTime, &sess.AMR, &sess.IP, &sess.UserAgent,
		&sess.CreatedAt, &sess.LastSeenAt, &sess.ExpiresAt, &sess.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}
	return &sess, nil
}

// UpdateSessionLastSeen updates last_seen_at for a session.
func (s *Store) UpdateSessionLastSeen(ctx context.Context, idHash []byte) error {
	query := `
		UPDATE sessions
		SET last_seen_at = now()
		WHERE id_hash = $1 AND revoked_at IS NULL AND expires_at > now()
	`
	cmd, err := s.pool.Exec(ctx, query, idHash)
	if err != nil {
		return fmt.Errorf("failed to update session last seen: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeSession marks a session as revoked.
func (s *Store) RevokeSession(ctx context.Context, idHash []byte) error {
	query := `
		UPDATE sessions
		SET revoked_at = now()
		WHERE id_hash = $1 AND revoked_at IS NULL
	`
	_, err := s.pool.Exec(ctx, query, idHash)
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Authorization Code Operations
// -------------------------------------------------------------------------

// CreateAuthCode inserts an authorization code.
func (s *Store) CreateAuthCode(ctx context.Context, code *AuthorizationCode) error {
	now := time.Now()
	if code.CreatedAt.IsZero() {
		code.CreatedAt = now
	}

	query := `
		INSERT INTO authorization_codes (
			code_hash, client_id, user_id, redirect_uri, scope, nonce,
			code_challenge, auth_time, amr, session_hash, expires_at,
			used_at, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
		)
	`
	_, err := s.pool.Exec(ctx, query,
		code.CodeHash, code.ClientID, code.UserID, code.RedirectURI, code.Scope,
		code.Nonce, code.CodeChallenge, code.AuthTime, code.AMR, code.SessionHash,
		code.ExpiresAt, code.UsedAt, code.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create authorization code: %w", err)
	}
	return nil
}

// ConsumeAuthCode atomically marks an unused code as used and returns its data.
// If the code was already used or expired, it returns ErrCodeAlreadyUsed or ErrNotFound.
func (s *Store) ConsumeAuthCode(ctx context.Context, codeHash []byte) (*AuthorizationCode, error) {
	query := `
		UPDATE authorization_codes
		SET used_at = now()
		WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING code_hash, client_id, user_id, redirect_uri, scope, nonce,
		          code_challenge, auth_time, amr, session_hash, expires_at,
		          used_at, created_at
	`
	var c AuthorizationCode
	err := s.pool.QueryRow(ctx, query, codeHash).Scan(
		&c.CodeHash, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope, &c.Nonce,
		&c.CodeChallenge, &c.AuthTime, &c.AMR, &c.SessionHash, &c.ExpiresAt,
		&c.UsedAt, &c.CreatedAt,
	)
	if err == nil {
		return &c, nil
	}

	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("failed to consume authorization code: %w", err)
	}

	// Code was not consumed in atomic UPDATE; check if it existed and was already used or expired
	checkQuery := `
		SELECT code_hash, client_id, user_id, redirect_uri, scope, nonce,
		       code_challenge, auth_time, amr, session_hash, expires_at,
		       used_at, created_at
		FROM authorization_codes
		WHERE code_hash = $1
	`
	var existing AuthorizationCode
	checkErr := s.pool.QueryRow(ctx, checkQuery, codeHash).Scan(
		&existing.CodeHash, &existing.ClientID, &existing.UserID, &existing.RedirectURI,
		&existing.Scope, &existing.Nonce, &existing.CodeChallenge, &existing.AuthTime,
		&existing.AMR, &existing.SessionHash, &existing.ExpiresAt, &existing.UsedAt,
		&existing.CreatedAt,
	)
	if checkErr != nil {
		if errors.Is(checkErr, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to check existing authorization code: %w", checkErr)
	}

	if existing.UsedAt != nil {
		return &existing, ErrCodeAlreadyUsed
	}
	if time.Now().After(existing.ExpiresAt) {
		return &existing, ErrCodeExpired
	}

	return nil, ErrNotFound
}

// -------------------------------------------------------------------------
// Refresh Token Operations
// -------------------------------------------------------------------------

// CreateRefreshToken inserts a new refresh token.
func (s *Store) CreateRefreshToken(ctx context.Context, rt *RefreshToken) error {
	now := time.Now()
	if rt.IssuedAt.IsZero() {
		rt.IssuedAt = now
	}

	query := `
		INSERT INTO refresh_tokens (
			id, token_hash, family_id, parent_id, client_id, user_id,
			scope, session_hash, issued_at, expires_at, absolute_expires_at,
			rotated_at, revoked_at, revoked_reason
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
	`
	_, err := s.pool.Exec(ctx, query,
		rt.ID, rt.TokenHash, rt.FamilyID, rt.ParentID, rt.ClientID, rt.UserID,
		rt.Scope, rt.SessionHash, rt.IssuedAt, rt.ExpiresAt, rt.AbsoluteExpiresAt,
		rt.RotatedAt, rt.RevokedAt, rt.RevokedReason,
	)
	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}
	return nil
}

// RotateRefreshTokenTx rotates a refresh token inside a transaction with row locking.
// Returns the old token (to inspect rotated_at / revoked_at) and handles rotation or family revocation.
func (s *Store) RotateRefreshTokenTx(ctx context.Context, tx pgx.Tx, oldTokenHash []byte, newChild *RefreshToken) (*RefreshToken, error) {
	// SELECT FOR UPDATE to prevent race conditions
	selectQuery := `
		SELECT id, token_hash, family_id, parent_id, client_id, user_id,
		       scope, session_hash, issued_at, expires_at, absolute_expires_at,
		       rotated_at, revoked_at, revoked_reason
		FROM refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`
	var old RefreshToken
	err := tx.QueryRow(ctx, selectQuery, oldTokenHash).Scan(
		&old.ID, &old.TokenHash, &old.FamilyID, &old.ParentID, &old.ClientID, &old.UserID,
		&old.Scope, &old.SessionHash, &old.IssuedAt, &old.ExpiresAt, &old.AbsoluteExpiresAt,
		&old.RotatedAt, &old.RevokedAt, &old.RevokedReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to query refresh token for update: %w", err)
	}

	// If already rotated or revoked, reuse is detected!
	if old.RotatedAt != nil || old.RevokedAt != nil {
		// Revoke the entire family
		reason := "reuse_detected"
		_, revErr := tx.Exec(ctx, `
			UPDATE refresh_tokens
			SET revoked_at = now(), revoked_reason = $1
			WHERE family_id = $2 AND revoked_at IS NULL
		`, reason, old.FamilyID)
		if revErr != nil {
			return nil, fmt.Errorf("failed to revoke token family on reuse: %w", revErr)
		}
		return &old, errors.New("refresh token reuse detected")
	}

	// Check expiry
	now := time.Now()
	if now.After(old.ExpiresAt) || now.After(old.AbsoluteExpiresAt) {
		return &old, errors.New("refresh token expired")
	}

	// Mark old token as rotated
	_, err = tx.Exec(ctx, `
		UPDATE refresh_tokens
		SET rotated_at = now()
		WHERE id = $1
	`, old.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to update rotated_at: %w", err)
	}

	// Insert child token
	if newChild.IssuedAt.IsZero() {
		newChild.IssuedAt = now
	}
	newChild.FamilyID = old.FamilyID
	newChild.ParentID = &old.ID
	if newChild.UserID == uuid.Nil {
		newChild.UserID = old.UserID
	}
	if newChild.ClientID == "" {
		newChild.ClientID = old.ClientID
	}
	if newChild.Scope == "" {
		newChild.Scope = old.Scope
	}
	if newChild.SessionHash == nil {
		newChild.SessionHash = old.SessionHash
	}

	insertQuery := `
		INSERT INTO refresh_tokens (
			id, token_hash, family_id, parent_id, client_id, user_id,
			scope, session_hash, issued_at, expires_at, absolute_expires_at,
			rotated_at, revoked_at, revoked_reason
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
	`
	_, err = tx.Exec(ctx, insertQuery,
		newChild.ID, newChild.TokenHash, newChild.FamilyID, newChild.ParentID,
		newChild.ClientID, newChild.UserID, newChild.Scope, newChild.SessionHash,
		newChild.IssuedAt, newChild.ExpiresAt, newChild.AbsoluteExpiresAt,
		nil, nil, nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert rotated child refresh token: %w", err)
	}

	return &old, nil
}

// RevokeFamilyByCodeRevocation revokes any refresh tokens associated with a user and client when code reuse is detected.
func (s *Store) RevokeTokensByUserAndClient(ctx context.Context, userID uuid.UUID, clientID string, reason string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = now(), revoked_reason = $1
		WHERE user_id = $2 AND client_id = $3 AND revoked_at IS NULL
	`
	_, err := s.pool.Exec(ctx, query, reason, userID, clientID)
	if err != nil {
		return fmt.Errorf("failed to revoke tokens by user and client: %w", err)
	}
	return nil
}

// -------------------------------------------------------------------------
// Consent Operations
// -------------------------------------------------------------------------

// GetConsent retrieves consent for a user and client.
func (s *Store) GetConsent(ctx context.Context, userID uuid.UUID, clientID string) (*Consent, error) {
	query := `
		SELECT user_id, client_id, scope, granted_at
		FROM consents
		WHERE user_id = $1 AND client_id = $2
	`
	var c Consent
	err := s.pool.QueryRow(ctx, query, userID, clientID).Scan(
		&c.UserID, &c.ClientID, &c.Scope, &c.GrantedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to get consent: %w", err)
	}
	return &c, nil
}

// SaveConsent inserts or updates consent.
func (s *Store) SaveConsent(ctx context.Context, c *Consent) error {
	now := time.Now()
	if c.GrantedAt.IsZero() {
		c.GrantedAt = now
	}

	query := `
		INSERT INTO consents (user_id, client_id, scope, granted_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (user_id, client_id)
		DO UPDATE SET scope = EXCLUDED.scope, granted_at = EXCLUDED.granted_at
	`
	_, err := s.pool.Exec(ctx, query, c.UserID, c.ClientID, c.Scope, c.GrantedAt)
	if err != nil {
		return fmt.Errorf("failed to save consent: %w", err)
	}
	return nil
}
