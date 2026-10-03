package discovery

import (
	"encoding/json"
	"net/http"
)

// Metadata represents the OpenID Provider Configuration / OAuth 2.0 Authorization Server Metadata.
type Metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// NewMetadata builds discovery metadata from the issuer URL.
func NewMetadata(issuer string) Metadata {
	return Metadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/authorize",
		TokenEndpoint:                     issuer + "/token",
		UserinfoEndpoint:                  issuer + "/userinfo",
		JwksURI:                           issuer + "/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "client_credentials", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		SubjectTypesSupported:             []string{"public"},
		ClaimsSupported: []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash",
			"email", "email_verified", "name", "preferred_username", "updated_at",
		},
	}
}

// Handler returns an http.HandlerFunc that serves discovery metadata.
func Handler(issuer string) http.HandlerFunc {
	meta := NewMetadata(issuer)
	data, _ := json.Marshal(meta)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	}
}
