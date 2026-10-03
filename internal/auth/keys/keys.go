package keys

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	StatusPending = "pending"
	StatusActive  = "active"
	StatusRetired = "retired"
	StatusRevoked = "revoked"

	AlgorithmRS256 = "RS256"
)

var (
	ErrNoActiveKey = errors.New("no active signing key available")
	ErrKeyNotFound = errors.New("signing key not found")
)

// SigningKey holds decrypted private key and metadata.
type SigningKey struct {
	KID        string
	Algorithm  string
	Status     string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	PublicJWK  jose.JSONWebKey
	CreatedAt  time.Time
}

// Manager coordinates signing key generation, master key encryption, rotation, and JWKS caching.
type Manager struct {
	pool      *pgxpool.Pool
	masterKey []byte // 32 bytes AES key
	mu        sync.RWMutex
	cachedKID string
	cachedKey *SigningKey
	jwksCache []byte
}

// NewManager creates a KeyManager.
func NewManager(pool *pgxpool.Pool, masterKey []byte) (*Manager, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be exactly 32 bytes for AES-256-GCM")
	}
	return &Manager{
		pool:      pool,
		masterKey: masterKey,
	}, nil
}

// EnsureActiveKey ensures that at least one active signing key exists; if none exists, generates one.
func (m *Manager) EnsureActiveKey(ctx context.Context) (*SigningKey, error) {
	key, err := m.GetActiveKey(ctx)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, ErrNoActiveKey) {
		return nil, err
	}

	// Generate and activate initial key (2048 or 3072 bits)
	return m.RotateKey(ctx, 2048)
}

// GenerateRSAKey creates a new RSA key pair, computes the RFC 7638 thumbprint, and encrypts the private key with AES-256-GCM.
func (m *Manager) GenerateRSAKey(bits int) (*SigningKey, []byte, error) {
	if bits < 2048 {
		bits = 2048
	}

	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	rawJWK := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		Algorithm: AlgorithmRS256,
		Use:       "sig",
	}

	thumbprint, err := rawJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute RFC 7638 thumbprint: %w", err)
	}
	kid := base64.RawURLEncoding.EncodeToString(thumbprint)
	rawJWK.KeyID = kid

	// Encrypt private key with AES-256-GCM using masterKey, AAD = kid
	privDER := x509.MarshalPKCS1PrivateKey(privKey)
	encryptedPriv, err := encryptAESGCM(m.masterKey, kid, privDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	return &SigningKey{
		KID:        kid,
		Algorithm:  AlgorithmRS256,
		Status:     StatusPending,
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		PublicJWK:  rawJWK.Public(),
		CreatedAt:  time.Now(),
	}, encryptedPriv, nil
}

// RotateKey generates a new key and sets it to active, retiring any prior active key.
func (m *Manager) RotateKey(ctx context.Context, bits int) (*SigningKey, error) {
	key, encryptedPriv, err := m.GenerateRSAKey(bits)
	if err != nil {
		return nil, err
	}

	publicJWKBytes, err := json.Marshal(key.PublicJWK)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public JWK: %w", err)
	}

	if m.pool != nil {
		tx, err := m.pool.Begin(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to begin transaction: %w", err)
		}
		defer tx.Rollback(ctx) //nolint:errcheck

		// Retire current active key
		_, err = tx.Exec(ctx, `
			UPDATE signing_keys 
			SET status = $1, retire_at = now() 
			WHERE status = $2
		`, StatusRetired, StatusActive)
		if err != nil {
			return nil, fmt.Errorf("failed to retire active key: %w", err)
		}

		// Insert new active key
		now := time.Now()
		_, err = tx.Exec(ctx, `
			INSERT INTO signing_keys (kid, alg, public_jwk, private_enc, status, created_at, activate_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, key.KID, key.Algorithm, publicJWKBytes, encryptedPriv, StatusActive, now, now)
		if err != nil {
			return nil, fmt.Errorf("failed to insert new active key: %w", err)
		}

		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit rotation transaction: %w", err)
		}
	}

	key.Status = StatusActive

	m.mu.Lock()
	m.cachedKID = key.KID
	m.cachedKey = key
	m.jwksCache = nil // Invalidate JWKS cache
	m.mu.Unlock()

	return key, nil
}

// GetActiveKey returns the currently active signing key.
func (m *Manager) GetActiveKey(ctx context.Context) (*SigningKey, error) {
	m.mu.RLock()
	if m.cachedKey != nil && m.cachedKey.Status == StatusActive {
		key := m.cachedKey
		m.mu.RUnlock()
		return key, nil
	}
	m.mu.RUnlock()

	if m.pool == nil {
		return nil, ErrNoActiveKey
	}

	var kid, alg, status string
	var publicJWKBytes, privateEnc []byte
	var createdAt time.Time

	err := m.pool.QueryRow(ctx, `
		SELECT kid, alg, public_jwk, private_enc, status, created_at
		FROM signing_keys
		WHERE status = $1
		ORDER BY created_at DESC
		LIMIT 1
	`, StatusActive).Scan(&kid, &alg, &publicJWKBytes, &privateEnc, &status, &createdAt)
	if err != nil {
		return nil, ErrNoActiveKey
	}

	privDER, err := decryptAESGCM(m.masterKey, kid, privateEnc)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key for kid %s: %w", kid, err)
	}

	privKey, err := x509.ParsePKCS1PrivateKey(privDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	var publicJWK jose.JSONWebKey
	if err := json.Unmarshal(publicJWKBytes, &publicJWK); err != nil {
		return nil, fmt.Errorf("failed to parse public JWK: %w", err)
	}

	key := &SigningKey{
		KID:        kid,
		Algorithm:  alg,
		Status:     status,
		PrivateKey: privKey,
		PublicKey:  &privKey.PublicKey,
		PublicJWK:  publicJWK,
		CreatedAt:  createdAt,
	}

	m.mu.Lock()
	m.cachedKID = kid
	m.cachedKey = key
	m.mu.Unlock()

	return key, nil
}

// GetPublicJWKS returns public keys in JSON Web Key Set format (never containing private key components).
func (m *Manager) GetPublicJWKS(ctx context.Context) ([]byte, error) {
	m.mu.RLock()
	if len(m.jwksCache) > 0 {
		data := m.jwksCache
		m.mu.RUnlock()
		return data, nil
	}
	m.mu.RUnlock()

	keysList := make([]jose.JSONWebKey, 0)

	if m.pool != nil {
		rows, err := m.pool.Query(ctx, `
			SELECT public_jwk
			FROM signing_keys
			WHERE status IN ($1, $2, $3)
			ORDER BY created_at DESC
		`, StatusActive, StatusPending, StatusRetired)
		if err != nil {
			return nil, fmt.Errorf("failed to query signing keys: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var rawJSON []byte
			if err := rows.Scan(&rawJSON); err != nil {
				return nil, err
			}
			var jwk jose.JSONWebKey
			if err := json.Unmarshal(rawJSON, &jwk); err != nil {
				return nil, err
			}
			// Enforce public only
			keysList = append(keysList, jwk.Public())
		}
	} else {
		m.mu.RLock()
		if m.cachedKey != nil {
			keysList = append(keysList, m.cachedKey.PublicJWK)
		}
		m.mu.RUnlock()
	}

	jwks := jose.JSONWebKeySet{
		Keys: keysList,
	}

	jwksBytes, err := json.Marshal(jwks)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWKS: %w", err)
	}

	m.mu.Lock()
	m.jwksCache = jwksBytes
	m.mu.Unlock()

	return jwksBytes, nil
}

// Handler returns the HTTP handler for /jwks.json per §6.8.
func (m *Manager) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jwksBytes, err := m.GetPublicJWKS(r.Context())
		if err != nil {
			http.Error(w, `{"error":"server_error","error_description":"failed to fetch jwks"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jwksBytes)
	}
}

// AES-256-GCM encryption with 12-byte random nonce and AAD.
func encryptAESGCM(key []byte, aad string, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, []byte(aad))

	// Prepend nonce to ciphertext
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out, nonce)
	copy(out[len(nonce):], ciphertext)

	return out, nil
}

// AES-256-GCM decryption.
func decryptAESGCM(key []byte, aad string, encrypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, []byte(aad))
}
