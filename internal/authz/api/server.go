package api

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/authz/engine"
	"github.com/raviteja-core/keystone/internal/authz/store"
	"github.com/raviteja-core/keystone/internal/platform/httpx"
)

// ServerConfig contains configuration options for the Authz HTTP API server.
type ServerConfig struct {
	MaxBodyBytes int64
}

// DefaultServerConfig returns standard defaults (1 MiB max body size).
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		MaxBodyBytes: 1 << 20, // 1 MiB
	}
}

// NewServerMux constructs and returns the HTTP ServeMux for the Authz engine API.
func NewServerMux(pool *pgxpool.Pool, s *store.Store, eng *engine.Engine, auth *Authenticator, cfg ServerConfig) http.Handler {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}

	mux := http.NewServeMux()

	// Root info endpoint
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"service": "keystone-authz",
			"version": "0.1.0",
		})
	})

	schemaH := NewSchemaHandler(pool, s, eng)
	relH := NewRelationshipsHandler(pool, s)
	checkH := NewCheckHandler(pool, s, eng)
	expandH := NewExpandHandler(pool, s)

	// Routes with scope enforcement
	// 1. Schema
	mux.Handle("PUT /v1/schema", auth.RequireScope("authz:admin")(http.HandlerFunc(schemaH.HandlePutSchema)))
	mux.Handle("GET /v1/schema", auth.RequireScope("authz:read")(http.HandlerFunc(schemaH.HandleGetSchema)))

	// 2. Relationships
	mux.Handle("POST /v1/relationships/write", auth.RequireScope("authz:write")(http.HandlerFunc(relH.HandleWriteRelationships)))
	mux.Handle("POST /v1/relationships/read", auth.RequireScope("authz:read")(http.HandlerFunc(relH.HandleReadRelationships)))

	// 3. Check & Batch Check
	mux.Handle("POST /v1/check", auth.RequireScope("authz:check")(http.HandlerFunc(checkH.HandleCheck)))
	mux.Handle("POST /v1/check/batch", auth.RequireScope("authz:check")(http.HandlerFunc(checkH.HandleBatchCheck)))

	// 4. Expand
	mux.Handle("POST /v1/expand", auth.RequireScope("authz:read")(http.HandlerFunc(expandH.HandleExpand)))

	// Wrap in standard body limits and security headers
	return httpx.MaxBodyBytes(cfg.MaxBodyBytes)(
		httpx.SecurityHeaders(mux),
	)
}
