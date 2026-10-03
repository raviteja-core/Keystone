package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/authz/engine"
	"github.com/raviteja-core/keystone/internal/authz/store"
)

type CheckHandler struct {
	pool   *pgxpool.Pool
	store  *store.Store
	engine *engine.Engine
}

func NewCheckHandler(pool *pgxpool.Pool, s *store.Store, eng *engine.Engine) *CheckHandler {
	return &CheckHandler{
		pool:   pool,
		store:  s,
		engine: eng,
	}
}

// HandleCheck handles POST /v1/check (scope: authz:check).
func (h *CheckHandler) HandleCheck(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantFromContext(r.Context())
	if tenantID == "" {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing tenant context")
		return
	}

	var req CheckRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid JSON", fmt.Sprintf("malformed request body: %v", err))
		return
	}
	defer r.Body.Close()

	objRef := req.GetObjectRef()
	if objRef == nil || objRef.Type == "" || objRef.ID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Missing Resource", ErrMissingResource.Error())
		return
	}
	if req.Permission == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Missing Permission", ErrMissingPermission.Error())
		return
	}
	if req.Subject.Type == "" || req.Subject.ID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Missing Subject", ErrMissingSubject.Error())
		return
	}

	ctx := r.Context()

	// 1. Resolve consistency & revision
	rev, err := h.resolveRevision(ctx, tenantID, req.Consistency)
	if err != nil {
		var zookieMismatch bool
		if errors.Is(err, store.ErrZookieTenantMismatch) {
			zookieMismatch = true
		}
		if zookieMismatch {
			WriteProblem(w, r, http.StatusBadRequest, "Zookie Tenant Mismatch", err.Error())
			return
		}
		if errors.Is(err, store.ErrTenantNotFound) {
			WriteProblem(w, r, http.StatusNotFound, "Tenant Not Found", "tenant does not exist")
			return
		}
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Consistency", err.Error())
		return
	}

	// 2. Tenant must have a configured schema
	_, _, err = h.store.GetLatestSchema(ctx, tenantID)
	if err != nil {
		if errors.Is(err, store.ErrNoSchema) || errors.Is(err, store.ErrTenantNotFound) {
			WriteProblem(w, r, http.StatusBadRequest, "No Schema", "tenant has no schema configured; initialize with PUT /v1/schema first")
			return
		}
		WriteProblem(w, r, http.StatusInternalServerError, "Database Error", "failed to check tenant schema")
		return
	}

	// 3. Perform authorization check
	engReq := engine.CheckRequest{
		TenantID: tenantID,
		Revision: rev,
		Object: store.Object{
			Type: objRef.Type,
			ID:   objRef.ID,
		},
		Permission: req.Permission,
		Subject: store.Subject{
			Type:     req.Subject.Type,
			ID:       req.Subject.ID,
			Relation: req.Subject.Relation,
		},
	}

	checkResp, err := h.engine.Check(ctx, engReq)
	if err != nil {
		switch {
		case errors.Is(err, engine.ErrUnknownType),
			errors.Is(err, engine.ErrUnknownRelationOrPermission),
			errors.Is(err, engine.ErrInvalidSubject):
			WriteProblem(w, r, http.StatusBadRequest, "Unknown Relation Or Type", err.Error())
		case errors.Is(err, engine.ErrDepthExceeded):
			WriteProblem(w, r, http.StatusBadRequest, "Depth Exceeded", err.Error())
		case errors.Is(err, engine.ErrResourceExhausted):
			WriteProblem(w, r, http.StatusTooManyRequests, "Resource Limit Exceeded", err.Error())
		case errors.Is(err, engine.ErrCycleCutoffInSubtrahend):
			WriteProblem(w, r, http.StatusInternalServerError, "Evaluation Error", err.Error())
		default:
			WriteProblem(w, r, http.StatusInternalServerError, "Check Failed", fmt.Sprintf("evaluation failed: %v", err))
		}
		return
	}

	resp := CheckResponseDTO{
		Allowed:   checkResp.Allowed,
		CheckedAt: store.EncodeZookie(tenantID, rev),
		Evaluation: EvaluationDTO{
			Depth:   checkResp.Depth,
			DBReads: checkResp.DBReads,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleBatchCheck handles POST /v1/check/batch (scope: authz:check).
func (h *CheckHandler) HandleBatchCheck(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantFromContext(r.Context())
	if tenantID == "" {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing tenant context")
		return
	}

	var req BatchCheckRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid JSON", fmt.Sprintf("malformed request body: %v", err))
		return
	}
	defer r.Body.Close()

	if len(req.Checks) == 0 {
		WriteProblem(w, r, http.StatusBadRequest, "Empty Batch", ErrBatchEmpty.Error())
		return
	}
	if len(req.Checks) > 100 {
		WriteProblem(w, r, http.StatusBadRequest, "Batch Too Large", ErrBatchTooLarge.Error())
		return
	}

	ctx := r.Context()

	// 1. Resolve consistency & revision ONCE for the entire batch
	rev, err := h.resolveRevision(ctx, tenantID, req.Consistency)
	if err != nil {
		if errors.Is(err, store.ErrZookieTenantMismatch) {
			WriteProblem(w, r, http.StatusBadRequest, "Zookie Tenant Mismatch", err.Error())
			return
		}
		if errors.Is(err, store.ErrTenantNotFound) {
			WriteProblem(w, r, http.StatusNotFound, "Tenant Not Found", "tenant does not exist")
			return
		}
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Consistency", err.Error())
		return
	}

	// 2. Tenant must have a configured schema
	_, _, err = h.store.GetLatestSchema(ctx, tenantID)
	if err != nil {
		if errors.Is(err, store.ErrNoSchema) || errors.Is(err, store.ErrTenantNotFound) {
			WriteProblem(w, r, http.StatusBadRequest, "No Schema", "tenant has no schema configured; initialize with PUT /v1/schema first")
			return
		}
		WriteProblem(w, r, http.StatusInternalServerError, "Database Error", "failed to check tenant schema")
		return
	}

	// 3. Execute all checks concurrently with bounded concurrency
	results := make([]BatchCheckItemResultDTO, len(req.Checks))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 16)

	for i, item := range req.Checks {
		wg.Add(1)
		go func(idx int, c CheckRequestDTO) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			objRef := c.GetObjectRef()
			if objRef == nil || objRef.Type == "" || objRef.ID == "" {
				results[idx] = BatchCheckItemResultDTO{
					Allowed: false,
					Error:   ErrMissingResource.Error(),
				}
				return
			}
			if c.Permission == "" {
				results[idx] = BatchCheckItemResultDTO{
					Allowed: false,
					Error:   ErrMissingPermission.Error(),
				}
				return
			}
			if c.Subject.Type == "" || c.Subject.ID == "" {
				results[idx] = BatchCheckItemResultDTO{
					Allowed: false,
					Error:   ErrMissingSubject.Error(),
				}
				return
			}

			engReq := engine.CheckRequest{
				TenantID: tenantID,
				Revision: rev,
				Object: store.Object{
					Type: objRef.Type,
					ID:   objRef.ID,
				},
				Permission: c.Permission,
				Subject: store.Subject{
					Type:     c.Subject.Type,
					ID:       c.Subject.ID,
					Relation: c.Subject.Relation,
				},
			}

			resp, cErr := h.engine.Check(ctx, engReq)
			if cErr != nil {
				results[idx] = BatchCheckItemResultDTO{
					Allowed: false,
					Error:   cErr.Error(),
				}
				return
			}

			results[idx] = BatchCheckItemResultDTO{
				Allowed: resp.Allowed,
				Evaluation: &EvaluationDTO{
					Depth:   resp.Depth,
					DBReads: resp.DBReads,
				},
			}
		}(i, item)
	}

	wg.Wait()

	resp := BatchCheckResponseDTO{
		CheckedAt: store.EncodeZookie(tenantID, rev),
		Results:   results,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *CheckHandler) resolveRevision(ctx context.Context, tenantID string, consistency *ConsistencyDTO) (int64, error) {
	currentRev, err := h.store.GetTenantRevision(ctx, tenantID)
	if err != nil {
		return 0, err
	}

	if consistency != nil && consistency.Token != "" {
		z, err := store.DecodeZookie(consistency.Token)
		if err != nil {
			return 0, err
		}
		if z.Tenant != tenantID {
			return 0, store.ErrZookieTenantMismatch
		}
		if currentRev < z.Revision {
			return z.Revision, nil
		}
		return currentRev, nil
	}

	return currentRev, nil
}
