package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/authz/schema"
	"github.com/raviteja-core/keystone/internal/authz/store"
)

type ExpandHandler struct {
	pool  *pgxpool.Pool
	store *store.Store
}

func NewExpandHandler(pool *pgxpool.Pool, s *store.Store) *ExpandHandler {
	return &ExpandHandler{
		pool:  pool,
		store: s,
	}
}

// HandleExpand handles POST /v1/expand (scope: authz:read).
func (h *ExpandHandler) HandleExpand(w http.ResponseWriter, r *http.Request) {
	tenantID := TenantFromContext(r.Context())
	if tenantID == "" {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing tenant context")
		return
	}

	var req ExpandRequestDTO
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

	ctx := r.Context()

	// 1. Resolve consistency
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

	// 2. Load latest schema
	sch, _, err := h.store.GetLatestSchema(ctx, tenantID)
	if err != nil {
		if errors.Is(err, store.ErrNoSchema) || errors.Is(err, store.ErrTenantNotFound) {
			WriteProblem(w, r, http.StatusBadRequest, "No Schema", "tenant has no schema configured; initialize with PUT /v1/schema first")
			return
		}
		WriteProblem(w, r, http.StatusInternalServerError, "Database Error", "failed to load schema")
		return
	}

	typeDef, ok := sch.Types[objRef.Type]
	if !ok {
		WriteProblem(w, r, http.StatusBadRequest, "Unknown Type", fmt.Sprintf("type %q is not defined in schema", objRef.Type))
		return
	}

	obj := store.Object{Type: objRef.Type, ID: objRef.ID}
	tree, err := h.expandNode(ctx, tenantID, sch, typeDef, obj, req.Permission, rev, 0)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Expand Failed", err.Error())
		return
	}

	resp := ExpandResponseDTO{
		Tree: tree,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *ExpandHandler) expandNode(ctx context.Context, tenantID string, sch *schema.Schema, typeDef *schema.TypeDefinition, obj store.Object, name string, rev int64, depth int) (*ExpandTreeNodeDTO, error) {
	if depth > 10 {
		return &ExpandTreeNodeDTO{
			Type:     "leaf",
			Target:   &ObjectRef{Type: obj.Type, ID: obj.ID},
			Relation: name,
		}, nil
	}

	// Case A: name is a permission
	if permDef, ok := typeDef.Permissions[name]; ok {
		return h.expandAST(ctx, tenantID, sch, typeDef, obj, permDef.AST, rev, depth)
	}

	// Case B: name is a relation
	if _, ok := typeDef.Relations[name]; ok {
		tuples, err := h.store.ReadTuples(ctx, tenantID, store.TupleFilter{
			ObjectType: obj.Type,
			ObjectID:   obj.ID,
			Relation:   name,
		}, rev)
		if err != nil {
			return nil, err
		}

		var children []*ExpandTreeNodeDTO
		for _, t := range tuples {
			children = append(children, &ExpandTreeNodeDTO{
				Type: "leaf",
				Subject: &SubjectRef{
					Type:     t.SubjectType,
					ID:       t.SubjectID,
					Relation: t.SubjectRelation,
				},
			})
		}

		return &ExpandTreeNodeDTO{
			Type:     "leaf",
			Target:   &ObjectRef{Type: obj.Type, ID: obj.ID},
			Relation: name,
			Children: children,
		}, nil
	}

	return nil, fmt.Errorf("name %q is neither a relation nor a permission on type %q", name, obj.Type)
}

func (h *ExpandHandler) expandAST(ctx context.Context, tenantID string, sch *schema.Schema, typeDef *schema.TypeDefinition, obj store.Object, node schema.Node, rev int64, depth int) (*ExpandTreeNodeDTO, error) {
	switch n := node.(type) {
	case *schema.NameNode:
		return h.expandNode(ctx, tenantID, sch, typeDef, obj, n.Name, rev, depth+1)

	case *schema.ArrowNode:
		// Read tuples for arrow relation
		tuples, err := h.store.ReadTuples(ctx, tenantID, store.TupleFilter{
			ObjectType: obj.Type,
			ObjectID:   obj.ID,
			Relation:   n.Relation,
		}, rev)
		if err != nil {
			return nil, err
		}

		var children []*ExpandTreeNodeDTO
		for _, t := range tuples {
			if t.SubjectRelation != "" || t.SubjectID == "*" {
				continue
			}
			targetTypeDef, ok := sch.Types[t.SubjectType]
			if !ok {
				continue
			}
			targetObj := store.Object{Type: t.SubjectType, ID: t.SubjectID}
			subTree, err := h.expandNode(ctx, tenantID, sch, targetTypeDef, targetObj, n.Permission, rev, depth+1)
			if err == nil {
				children = append(children, subTree)
			}
		}

		return &ExpandTreeNodeDTO{
			Type:     "arrow",
			Target:   &ObjectRef{Type: obj.Type, ID: obj.ID},
			Relation: fmt.Sprintf("%s->%s", n.Relation, n.Permission),
			Children: children,
		}, nil

	case *schema.BinaryNode:
		left, err := h.expandAST(ctx, tenantID, sch, typeDef, obj, n.Left, rev, depth+1)
		if err != nil {
			return nil, err
		}
		right, err := h.expandAST(ctx, tenantID, sch, typeDef, obj, n.Right, rev, depth+1)
		if err != nil {
			return nil, err
		}

		var opType string
		switch n.Op {
		case schema.NodeUnion:
			opType = "union"
		case schema.NodeIntersection:
			opType = "intersection"
		case schema.NodeExclusion:
			opType = "exclusion"
		default:
			opType = string(n.Op)
		}

		return &ExpandTreeNodeDTO{
			Type:     opType,
			Children: []*ExpandTreeNodeDTO{left, right},
		}, nil

	default:
		return nil, fmt.Errorf("unknown AST node type %T", node)
	}
}
