package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/authz/store"
)

type RelationshipsHandler struct {
	pool  *pgxpool.Pool
	store *store.Store
}

func NewRelationshipsHandler(pool *pgxpool.Pool, s *store.Store) *RelationshipsHandler {
	return &RelationshipsHandler{
		pool:  pool,
		store: s,
	}
}

// HandleWriteRelationships handles POST /v1/relationships/write (scope: authz:write).
func (h *RelationshipsHandler) HandleWriteRelationships(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantFromContext(r.Context())
	if tenantID == "" {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing tenant context")
		return
	}

	var req WriteRelationshipsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid JSON", fmt.Sprintf("malformed request body: %v", err))
		return
	}
	defer r.Body.Close()

	opsDTO := req.GetOperations()
	if len(opsDTO) > 1000 {
		WriteProblem(w, r, http.StatusBadRequest, "Batch Too Large", "write batch exceeds limit of 1000 operations")
		return
	}

	if len(opsDTO) == 0 && len(req.Preconditions) == 0 {
		WriteProblem(w, r, http.StatusBadRequest, "Empty Request", "request must contain at least one operation or precondition")
		return
	}

	// Map operations
	storeOps := make([]store.TupleOperation, len(opsDTO))
	for i, op := range opsDTO {
		storeOp := store.TupleOperation{
			Op:    op.Op,
			Tuple: op.Tuple.ToStoreTuple(tenantID),
		}
		storeOps[i] = storeOp
	}

	// Map preconditions
	storePre := make([]store.Precondition, len(req.Preconditions))
	for i, p := range req.Preconditions {
		storePre[i] = store.Precondition{
			Tuple:  p.Tuple.ToStoreTuple(tenantID),
			Exists: p.Exists,
		}
	}

	ctx := r.Context()
	newRev, err := h.store.WriteRelationshipsWithPreconditions(ctx, tenantID, storeOps, storePre)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrPreconditionFailed):
			WriteProblem(w, r, http.StatusPreconditionFailed, "Precondition Failed", err.Error())
		case errors.Is(err, store.ErrTupleAlreadyExists):
			WriteProblem(w, r, http.StatusConflict, "Tuple Already Exists", err.Error())
		case errors.Is(err, store.ErrNoSchema):
			WriteProblem(w, r, http.StatusBadRequest, "No Schema", "tenant has no schema configured; initialize with PUT /v1/schema first")
		case errors.Is(err, store.ErrTenantNotFound):
			WriteProblem(w, r, http.StatusBadRequest, "Tenant Not Found", "tenant does not exist; initialize with PUT /v1/schema first")
		case errors.Is(err, store.ErrSchemaValidation), errors.Is(err, store.ErrInvalidIdentifier):
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Tuple", err.Error())
		default:
			WriteProblem(w, r, http.StatusInternalServerError, "Write Failed", fmt.Sprintf("failed to write relationships: %v", err))
		}
		return
	}

	resp := WriteRelationshipsResponse{
		Zookie: store.EncodeZookie(tenantID, newRev),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// HandleReadRelationships handles POST /v1/relationships/read (scope: authz:read).
func (h *RelationshipsHandler) HandleReadRelationships(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantFromContext(r.Context())
	if tenantID == "" {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing tenant context")
		return
	}

	var req ReadRelationshipsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid JSON", fmt.Sprintf("malformed request body: %v", err))
		return
	}
	defer r.Body.Close()

	ctx := r.Context()

	// Resolve revision from consistency or current revision
	var rev int64
	if req.Consistency != nil && req.Consistency.Token != "" {
		z, err := store.DecodeZookie(req.Consistency.Token)
		if err != nil {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Zookie", err.Error())
			return
		}
		if z.Tenant != tenantID {
			WriteProblem(w, r, http.StatusBadRequest, "Zookie Tenant Mismatch", "zookie tenant does not match caller tenant")
			return
		}
		rev = z.Revision
	} else {
		currentRev, err := h.store.GetTenantRevision(ctx, tenantID)
		if err != nil {
			if errors.Is(err, store.ErrTenantNotFound) {
				WriteProblem(w, r, http.StatusNotFound, "Tenant Not Found", "tenant does not exist")
				return
			}
			WriteProblem(w, r, http.StatusInternalServerError, "Database Error", "failed to read tenant revision")
			return
		}
		rev = currentRev
	}

	// Build filter
	var subjRel *string
	if req.SubjectRelation != "" {
		subjRel = &req.SubjectRelation
	} else if req.Subject != nil && req.Subject.Relation != "" {
		subjRel = &req.Subject.Relation
	}

	filter := store.TupleFilter{
		ObjectType:      req.ObjectType,
		ObjectID:        req.ObjectID,
		Relation:        req.Relation,
		SubjectType:     req.SubjectType,
		SubjectID:       req.SubjectID,
		SubjectRelation: subjRel,
	}
	if req.Object != nil {
		if filter.ObjectType == "" {
			filter.ObjectType = req.Object.Type
		}
		if filter.ObjectID == "" {
			filter.ObjectID = req.Object.ID
		}
	}
	if req.Subject != nil {
		if filter.SubjectType == "" {
			filter.SubjectType = req.Subject.Type
		}
		if filter.SubjectID == "" {
			filter.SubjectID = req.Subject.ID
		}
	}

	tuples, err := h.store.ReadTuples(ctx, tenantID, filter, rev)
	if err != nil {
		WriteProblem(w, r, http.StatusInternalServerError, "Read Failed", fmt.Sprintf("failed to read tuples: %v", err))
		return
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 1000 {
		limit = 1000
	}

	var continuation string
	if len(tuples) > limit {
		tuples = tuples[:limit]
	}

	dtos := make([]TupleDTO, len(tuples))
	for i, t := range tuples {
		dtos[i] = FromStoreTuple(t)
	}

	resp := ReadRelationshipsResponse{
		Tuples:            dtos,
		ReadAt:            store.EncodeZookie(tenantID, rev),
		ContinuationToken: continuation,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
