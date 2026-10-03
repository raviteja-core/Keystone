package api

import (
	"errors"
	"strings"

	"github.com/raviteja-core/keystone/internal/authz/store"
)

var (
	ErrMissingResource   = errors.New("resource (or object) is required")
	ErrMissingPermission = errors.New("permission is required")
	ErrMissingSubject    = errors.New("subject is required")
	ErrBatchTooLarge     = errors.New("batch size exceeds limit of 100 checks")
	ErrBatchEmpty        = errors.New("batch must contain at least one check")
	ErrWriteBatchTooBig  = errors.New("write batch exceeds limit of 1000 operations")
)

// ObjectRef identifies an entity in the authorization graph.
type ObjectRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// SubjectRef identifies a subject (user, wildcard, or userset) in the authorization graph.
type SubjectRef struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Relation string `json:"relation,omitempty"`
}

// ConsistencyDTO specifies consistency requirements for read or check operations.
type ConsistencyDTO struct {
	Mode  string `json:"mode,omitempty"`  // "at_least_as_fresh", "fully_consistent", or "minimize_latency"
	Token string `json:"token,omitempty"` // zookie string, e.g. "v1.eyJ0Ijoi..."
}

// TupleDTO represents a relationship tuple in API requests and responses.
type TupleDTO struct {
	Object          *ObjectRef  `json:"object,omitempty"`
	Relation        string      `json:"relation,omitempty"`
	Subject         *SubjectRef `json:"subject,omitempty"`
	ObjectType      string      `json:"object_type,omitempty"`
	ObjectID        string      `json:"object_id,omitempty"`
	SubjectType     string      `json:"subject_type,omitempty"`
	SubjectID       string      `json:"subject_id,omitempty"`
	SubjectRelation string      `json:"subject_relation,omitempty"`
}

// ToStoreTuple normalizes structured and flat tuple fields into a store.Tuple.
func (t TupleDTO) ToStoreTuple(tenantID string) store.Tuple {
	res := store.Tuple{
		TenantID: tenantID,
	}

	if t.Object != nil {
		res.ObjectType = t.Object.Type
		res.ObjectID = t.Object.ID
	} else {
		res.ObjectType = t.ObjectType
		res.ObjectID = t.ObjectID
	}

	res.Relation = t.Relation

	if t.Subject != nil {
		res.SubjectType = t.Subject.Type
		res.SubjectID = t.Subject.ID
		res.SubjectRelation = t.Subject.Relation
	} else {
		res.SubjectType = t.SubjectType
		res.SubjectID = t.SubjectID
		res.SubjectRelation = t.SubjectRelation
	}

	return res
}

// FromStoreTuple converts a store.Tuple to a TupleDTO.
func FromStoreTuple(t store.Tuple) TupleDTO {
	return TupleDTO{
		Object: &ObjectRef{
			Type: t.ObjectType,
			ID:   t.ObjectID,
		},
		Relation: t.Relation,
		Subject: &SubjectRef{
			Type:     t.SubjectType,
			ID:       t.SubjectID,
			Relation: t.SubjectRelation,
		},
	}
}

// TupleOperationDTO represents an operation in a write batch.
type TupleOperationDTO struct {
	Op    string   `json:"op"` // "create", "touch", or "delete"
	Tuple TupleDTO `json:"tuple"`
}

// PreconditionDTO represents an existence check before applying write operations.
type PreconditionDTO struct {
	Tuple  TupleDTO `json:"tuple"`
	Exists bool     `json:"exists"`
}

// WriteRelationshipsRequest represents the body of POST /v1/relationships/write.
type WriteRelationshipsRequest struct {
	Updates       []TupleOperationDTO `json:"updates,omitempty"`
	Operations    []TupleOperationDTO `json:"operations,omitempty"`
	Preconditions []PreconditionDTO   `json:"preconditions,omitempty"`
}

// GetOperations returns the list of operations from Updates or Operations field.
func (w WriteRelationshipsRequest) GetOperations() []TupleOperationDTO {
	if len(w.Updates) > 0 {
		return w.Updates
	}
	return w.Operations
}

// WriteRelationshipsResponse represents the response of POST /v1/relationships/write.
type WriteRelationshipsResponse struct {
	Zookie string `json:"zookie"`
}

// ReadRelationshipsRequest represents the body of POST /v1/relationships/read.
type ReadRelationshipsRequest struct {
	Object            *ObjectRef      `json:"object,omitempty"`
	ObjectType        string          `json:"object_type,omitempty"`
	ObjectID          string          `json:"object_id,omitempty"`
	Relation          string          `json:"relation,omitempty"`
	Subject           *SubjectRef     `json:"subject,omitempty"`
	SubjectType       string          `json:"subject_type,omitempty"`
	SubjectID         string          `json:"subject_id,omitempty"`
	SubjectRelation   string          `json:"subject_relation,omitempty"`
	Limit             int             `json:"limit,omitempty"`
	ContinuationToken string          `json:"continuation_token,omitempty"`
	Consistency       *ConsistencyDTO `json:"consistency,omitempty"`
}

// ReadRelationshipsResponse represents the response of POST /v1/relationships/read.
type ReadRelationshipsResponse struct {
	Tuples            []TupleDTO `json:"tuples"`
	ReadAt            string     `json:"read_at"`
	ContinuationToken string     `json:"continuation_token,omitempty"`
}

// CheckRequestDTO represents the body of POST /v1/check.
type CheckRequestDTO struct {
	Resource    *ObjectRef      `json:"resource,omitempty"`
	Object      *ObjectRef      `json:"object,omitempty"`
	Permission  string          `json:"permission"`
	Subject     SubjectRef      `json:"subject"`
	Consistency *ConsistencyDTO `json:"consistency,omitempty"`
}

// GetObjectRef returns the object reference from either Resource or Object field.
func (c CheckRequestDTO) GetObjectRef() *ObjectRef {
	if c.Resource != nil {
		return c.Resource
	}
	return c.Object
}

// EvaluationDTO details the evaluation metrics for a check.
type EvaluationDTO struct {
	Depth   int `json:"depth"`
	DBReads int `json:"db_reads"`
}

// CheckResponseDTO represents the response of POST /v1/check.
type CheckResponseDTO struct {
	Allowed    bool          `json:"allowed"`
	CheckedAt  string        `json:"checked_at"`
	Evaluation EvaluationDTO `json:"evaluation"`
}

// BatchCheckRequestDTO represents the body of POST /v1/check/batch.
type BatchCheckRequestDTO struct {
	Checks      []CheckRequestDTO `json:"checks"`
	Consistency *ConsistencyDTO   `json:"consistency,omitempty"`
}

// BatchCheckItemResultDTO represents an individual check result in a batch.
type BatchCheckItemResultDTO struct {
	Allowed    bool           `json:"allowed"`
	Evaluation *EvaluationDTO `json:"evaluation,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// BatchCheckResponseDTO represents the response of POST /v1/check/batch.
type BatchCheckResponseDTO struct {
	CheckedAt string                    `json:"checked_at"`
	Results   []BatchCheckItemResultDTO `json:"results"`
}

// PutSchemaResponseDTO represents the response of PUT /v1/schema.
type PutSchemaResponseDTO struct {
	Version int    `json:"version"`
	Zookie  string `json:"zookie"`
}

// GetSchemaResponseDTO represents the response of GET /v1/schema.
type GetSchemaResponseDTO struct {
	Version    int    `json:"version"`
	Definition string `json:"definition"`
	CreatedAt  string `json:"created_at"`
}

// ExpandRequestDTO represents the body of POST /v1/expand.
type ExpandRequestDTO struct {
	Resource    *ObjectRef      `json:"resource,omitempty"`
	Object      *ObjectRef      `json:"object,omitempty"`
	Permission  string          `json:"permission"`
	Consistency *ConsistencyDTO `json:"consistency,omitempty"`
}

// GetObjectRef returns the object reference from Resource or Object.
func (e ExpandRequestDTO) GetObjectRef() *ObjectRef {
	if e.Resource != nil {
		return e.Resource
	}
	return e.Object
}

// ExpandTreeNodeDTO represents a node in the userset tree returned by POST /v1/expand.
type ExpandTreeNodeDTO struct {
	Type     string               `json:"type"` // "leaf", "union", "intersection", "exclusion"
	Target   *ObjectRef           `json:"target,omitempty"`
	Relation string               `json:"relation,omitempty"`
	Subject  *SubjectRef          `json:"subject,omitempty"`
	Children []*ExpandTreeNodeDTO `json:"children,omitempty"`
}

// ExpandResponseDTO represents the response of POST /v1/expand.
type ExpandResponseDTO struct {
	Tree *ExpandTreeNodeDTO `json:"tree"`
}

// HasScope checks if a space-separated scope string contains requiredScope or admin scope.
func HasScope(grantedScopes, requiredScope string) bool {
	fields := strings.Fields(grantedScopes)
	for _, s := range fields {
		if s == requiredScope || s == "authz:admin" {
			return true
		}
	}
	return false
}
