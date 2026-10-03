package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/authz/engine"
	"github.com/raviteja-core/keystone/internal/authz/schema"
	"github.com/raviteja-core/keystone/internal/authz/store"
)

type SchemaHandler struct {
	pool   *pgxpool.Pool
	store  *store.Store
	engine *engine.Engine
}

func NewSchemaHandler(pool *pgxpool.Pool, s *store.Store, eng *engine.Engine) *SchemaHandler {
	return &SchemaHandler{
		pool:   pool,
		store:  s,
		engine: eng,
	}
}

// HandlePutSchema handles PUT /v1/schema (scope: authz:admin).
func (h *SchemaHandler) HandlePutSchema(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantFromContext(r.Context())
	if tenantID == "" {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing tenant context")
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Bad Request", "failed to read request body")
		return
	}
	defer r.Body.Close()

	if len(bodyBytes) == 0 {
		WriteProblem(w, r, http.StatusBadRequest, "Bad Request", "schema definition cannot be empty")
		return
	}

	schemaText := string(bodyBytes)

	// Check if body was wrapped in JSON {"schema": "..."}
	var jsonWrapper struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(bodyBytes, &jsonWrapper); err == nil && jsonWrapper.Schema != "" {
		schemaText = jsonWrapper.Schema
	}

	// Validate and compile schema
	sch, err := schema.ParseAndValidate(schemaText)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Schema", err.Error())
		return
	}

	ctx := r.Context()

	// 1. Ensure tenant exists on first schema upload
	_, err = h.pool.Exec(ctx, `
		INSERT INTO authz_tenants (tenant_id, current_rev)
		VALUES ($1, 0)
		ON CONFLICT (tenant_id) DO NOTHING
	`, tenantID)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Database Error", "failed to initialize tenant")
		return
	}

	// 2. Determine next schema version for this tenant
	var nextVersion int
	err = h.pool.QueryRow(ctx, `
		SELECT COALESCE(MAX(version), 0) + 1
		FROM authz_schemas
		WHERE tenant_id = $1
	`, tenantID).Scan(&nextVersion)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Database Error", "failed to determine schema version")
		return
	}

	// 3. Save schema
	createdRev, err := h.store.SaveSchema(ctx, tenantID, nextVersion, schemaText, sch)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Database Error", fmt.Sprintf("failed to save schema: %v", err))
		return
	}

	// 4. Invalidate engine schema cache
	if h.engine != nil {
		h.engine.InvalidateSchema(tenantID)
	}

	resp := PutSchemaResponseDTO{
		Version: nextVersion,
		Zookie:  store.EncodeZookie(tenantID, createdRev),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleGetSchema handles GET /v1/schema (scope: authz:read).
func (h *SchemaHandler) HandleGetSchema(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantFromContext(r.Context())
	if tenantID == "" {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing tenant context")
		return
	}

	ctx := r.Context()
	versionStr := r.URL.Query().Get("version")

	var (
		version    int
		definition string
		createdAt  time.Time
		queryErr   error
	)

	if strings.TrimSpace(versionStr) != "" {
		v, err := strconv.Atoi(versionStr)
		if err != nil || v < 1 {
			WriteProblem(w, r, http.StatusBadRequest, "Bad Request", "invalid version parameter")
			return
		}

		query := `
			SELECT version, definition, created_at
			FROM authz_schemas
			WHERE tenant_id = $1 AND version = $2
		`
		queryErr = h.pool.QueryRow(ctx, query, tenantID, v).Scan(&version, &definition, &createdAt)
	} else {
		query := `
			SELECT version, definition, created_at
			FROM authz_schemas
			WHERE tenant_id = $1
			ORDER BY version DESC
			LIMIT 1
		`
		queryErr = h.pool.QueryRow(ctx, query, tenantID).Scan(&version, &definition, &createdAt)
	}

	if queryErr != nil {
		if errors.Is(queryErr, pgx.ErrNoRows) {
			WriteProblem(w, r, http.StatusNotFound, "Schema Not Found", "tenant has no schema configured for requested version")
			return
		}
		WriteProblem(w, r, http.StatusInternalServerError, "Database Error", "failed to retrieve schema")
		return
	}

	resp := GetSchemaResponseDTO{
		Version:    version,
		Definition: definition,
		CreatedAt:  createdAt.UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
