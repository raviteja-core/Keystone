package keystone

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TokenSource provides an OAuth2 Bearer token for authenticating calls to Keystone services.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

type staticTokenSource struct {
	token string
}

func (s staticTokenSource) Token(ctx context.Context) (string, error) {
	if s.token == "" {
		return "", errors.New("static token is empty")
	}
	return s.token, nil
}

// StaticTokenSource returns a TokenSource that always returns the provided token.
func StaticTokenSource(token string) TokenSource {
	return staticTokenSource{token: token}
}

// clientCredentialsTokenSource implements OAuth 2.0 client_credentials flow with in-memory token caching.
type clientCredentialsTokenSource struct {
	mu           sync.Mutex
	tokenURL     string
	clientID     string
	clientSecret string
	scope        string
	httpClient   *http.Client
	cachedToken  string
	expiresAt    time.Time
}

// ClientCredentialsOption configures the client credentials token source.
type ClientCredentialsOption func(*clientCredentialsTokenSource)

// WithClientCredentialsHTTPClient sets a custom HTTP client for client credentials token exchange.
func WithClientCredentialsHTTPClient(hc *http.Client) ClientCredentialsOption {
	return func(s *clientCredentialsTokenSource) {
		if hc != nil {
			s.httpClient = hc
		}
	}
}

// ClientCredentialsTokenSource creates a TokenSource using the OAuth 2.0 client credentials grant.
func ClientCredentialsTokenSource(tokenURL, clientID, clientSecret, scope string, opts ...ClientCredentialsOption) TokenSource {
	s := &clientCredentialsTokenSource{
		tokenURL:     tokenURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		scope:        scope,
		httpClient:   &http.Client{Timeout: 10 * time.Second},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *clientCredentialsTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Return cached token if valid for at least another 30 seconds
	if s.cachedToken != "" && time.Now().Add(30*time.Second).Before(s.expiresAt) {
		return s.cachedToken, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
	}
	if s.scope != "" {
		form.Set("scope", s.scope)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(bodyBytes, &tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", errors.New("token response missing access_token")
	}

	ttl := time.Duration(tokenResp.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}

	s.cachedToken = tokenResp.AccessToken
	s.expiresAt = time.Now().Add(ttl)

	return s.cachedToken, nil
}

// AuthzClient is the high-assurance API client for Keystone's Zanzibar ReBAC Authz Engine.
type AuthzClient struct {
	mu                 sync.RWMutex
	authzURL           string
	tokenSource        TokenSource
	httpClient         *http.Client
	latestZookie       string
	defaultConsistency *Consistency
}

// AuthzClientOption configures an AuthzClient.
type AuthzClientOption func(*AuthzClient)

// WithAuthzHTTPClient configures a custom HTTP client for the AuthzClient.
func WithAuthzHTTPClient(hc *http.Client) AuthzClientOption {
	return func(c *AuthzClient) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// WithDefaultConsistency sets a default consistency level applied when CheckRequest consistency is nil.
func WithDefaultConsistency(cons *Consistency) AuthzClientOption {
	return func(c *AuthzClient) {
		c.defaultConsistency = cons
	}
}

// NewAuthzClient creates a new client for Keystone's Authz Engine.
func NewAuthzClient(authzURL string, tokenSource TokenSource, opts ...AuthzClientOption) (*AuthzClient, error) {
	if authzURL == "" {
		return nil, errors.New("authzURL must not be empty")
	}

	c := &AuthzClient{
		authzURL:    strings.TrimRight(authzURL, "/"),
		tokenSource: tokenSource,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// LatestZookie returns the most recent consistency Zookie observed by this client.
func (c *AuthzClient) LatestZookie() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.latestZookie
}

// SetLatestZookie updates the client's observed Zookie.
func (c *AuthzClient) SetLatestZookie(zookie string) {
	if zookie == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.latestZookie = zookie
}

// Check evaluates whether a subject has a specific permission on an object.
func (c *AuthzClient) Check(ctx context.Context, req CheckRequest) (*CheckResponse, error) {
	if req.Object.Type == "" || req.Object.ID == "" {
		return nil, ErrMissingObject
	}
	if req.Permission == "" {
		return nil, ErrMissingPermission
	}
	if req.Subject.Type == "" || req.Subject.ID == "" {
		return nil, ErrSubjectMissing
	}

	// Apply default consistency if request didn't specify one
	if req.Consistency == nil && c.defaultConsistency != nil {
		req.Consistency = c.defaultConsistency
	}

	var resp CheckResponse
	if err := c.doPost(ctx, "/v1/check", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// BatchCheck evaluates a collection of permission checks in a single round-trip.
func (c *AuthzClient) BatchCheck(ctx context.Context, req BatchCheckRequest) (*BatchCheckResponse, error) {
	if len(req.Checks) == 0 {
		return nil, errors.New("batch checks must not be empty")
	}

	var resp BatchCheckResponse
	if err := c.doPost(ctx, "/v1/check/batch", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// WriteRelationships mutates relationship tuples in the Authz store.
func (c *AuthzClient) WriteRelationships(ctx context.Context, req WriteRelationshipsRequest) (*WriteRelationshipsResponse, error) {
	var resp WriteRelationshipsResponse
	if err := c.doPost(ctx, "/v1/relationships/write", req, &resp); err != nil {
		return nil, err
	}

	if resp.Zookie != "" {
		c.SetLatestZookie(resp.Zookie)
	}

	return &resp, nil
}

// ReadRelationships queries relationship tuples matching criteria.
func (c *AuthzClient) ReadRelationships(ctx context.Context, req ReadRelationshipsRequest) (*ReadRelationshipsResponse, error) {
	var resp ReadRelationshipsResponse
	if err := c.doPost(ctx, "/v1/relationships/read", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Expand returns the full userset tree for an object and permission.
func (c *AuthzClient) Expand(ctx context.Context, req ExpandRequest) (*ExpandResponse, error) {
	var resp ExpandResponse
	if err := c.doPost(ctx, "/v1/expand", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

func (c *AuthzClient) doPost(ctx context.Context, path string, reqPayload interface{}, out interface{}) error {
	endpoint := c.authzURL + path

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, application/problem+json")

	if c.tokenSource != nil {
		token, err := c.tokenSource.Token(ctx)
		if err != nil {
			return fmt.Errorf("obtain auth token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthzServiceUnavailable, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	// Capture response zookie header if present
	if zk := resp.Header.Get("X-Keystone-Zookie"); zk != "" {
		c.SetLatestZookie(zk)
	}

	if resp.StatusCode >= 400 {
		var prob ProblemDetails
		if err := json.Unmarshal(respBytes, &prob); err == nil && prob.Title != "" {
			return &prob
		}
		return fmt.Errorf("authz request failed with status %d: %s", resp.StatusCode, string(respBytes))
	}

	if out != nil {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}

	return nil
}
