package keystone

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// KeyProvider is a function that returns an RSA public key given a Key ID (kid).
type KeyProvider func(ctx context.Context, kid string) (*rsa.PublicKey, error)

// JWKSCache provides a thread-safe caching key provider backed by a remote JWKS endpoint.
type JWKSCache struct {
	mu                 sync.RWMutex
	jwksURL            string
	httpClient         *http.Client
	ttl                time.Duration
	minRefetchInterval time.Duration
	lastFetched        time.Time
	keys               map[string]*rsa.PublicKey
}

// NewJWKSCache creates a new JWKS cache fetching from jwksURL.
func NewJWKSCache(jwksURL string, httpClient *http.Client, ttl, minRefetchInterval time.Duration) *JWKSCache {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	if minRefetchInterval <= 0 {
		minRefetchInterval = 10 * time.Second
	}
	return &JWKSCache{
		jwksURL:            jwksURL,
		httpClient:         httpClient,
		ttl:                ttl,
		minRefetchInterval: minRefetchInterval,
		keys:               make(map[string]*rsa.PublicKey),
	}
}

// GetKey retrieves the public key matching kid. If kid is missing from cache or cache is expired,
// it triggers a refresh subject to rate limiting against DoS attacks.
func (c *JWKSCache) GetKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, exists := c.keys[kid]
	expired := time.Since(c.lastFetched) > c.ttl
	c.mu.RUnlock()

	if exists && !expired {
		return key, nil
	}

	// Lock to potentially refresh keys
	c.mu.Lock()
	defer c.mu.Unlock()

	// Re-check after acquiring write lock
	key, exists = c.keys[kid]
	expired = time.Since(c.lastFetched) > c.ttl
	if exists && !expired {
		return key, nil
	}

	// Rate-limit refetch if key was not found to prevent JWKS endpoint flooding
	if !expired && time.Since(c.lastFetched) < c.minRefetchInterval {
		if exists {
			return key, nil
		}
		return nil, fmt.Errorf("%w: kid %q not found in cached JWKS", ErrSigningKeyNotFound, kid)
	}

	if err := c.refreshLocked(ctx); err != nil {
		// If refresh failed but we still have an unexpired cached key, fall back to it
		if exists {
			return key, nil
		}
		return nil, fmt.Errorf("failed to refresh JWKS from %s: %w", c.jwksURL, err)
	}

	key, exists = c.keys[kid]
	if !exists {
		return nil, fmt.Errorf("%w: kid %q not present in remote JWKS", ErrSigningKeyNotFound, kid)
	}

	return key, nil
}

func (c *JWKSCache) refreshLocked(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("create JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d fetching JWKS from %s", resp.StatusCode, c.jwksURL)
	}

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}

	newKeys := make(map[string]*rsa.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.KeyID == "" {
			continue
		}
		if pubKey, ok := jwk.Key.(*rsa.PublicKey); ok {
			newKeys[jwk.KeyID] = pubKey
		}
	}

	c.keys = newKeys
	c.lastFetched = time.Now()
	return nil
}
