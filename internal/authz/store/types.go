package store

import (
	"errors"
	"fmt"
	"regexp"
)

var (
	typeRelRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	idRegex      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_\-|.@+/=:]{0,127}$`)
)

var (
	ErrInvalidIdentifier  = errors.New("invalid identifier")
	ErrTenantNotFound     = errors.New("tenant not found")
	ErrNoSchema           = errors.New("no schema configured for tenant")
	ErrTupleAlreadyExists = errors.New("tuple already exists")
	ErrSchemaValidation   = errors.New("tuple violates current schema")
)

// ValidateTypeOrRelation validates type or relation names against ^[a-z][a-z0-9_]{0,63}$.
func ValidateTypeOrRelation(s string) bool {
	return typeRelRegex.MatchString(s)
}

// ValidateID validates object or subject identifiers against ^[A-Za-z0-9_][A-Za-z0-9_\-|.@+/=:]{0,127}$ or '*'.
func ValidateID(s string, allowWildcard bool) bool {
	if allowWildcard && s == "*" {
		return true
	}
	return idRegex.MatchString(s)
}

// Object represents a typed resource entity (e.g. doc:42).
type Object struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

func (o Object) String() string {
	return o.Type + ":" + o.ID
}

// Subject represents a subject entity (user:alice, group:eng#member, or user:*).
type Subject struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Relation string `json:"relation,omitempty"`
}

func (s Subject) String() string {
	if s.Relation != "" {
		return fmt.Sprintf("%s:%s#%s", s.Type, s.ID, s.Relation)
	}
	return s.Type + ":" + s.ID
}

// Tuple represents a stored relationship fact.
type Tuple struct {
	TenantID        string `json:"tenant_id"`
	ObjectType      string `json:"object_type"`
	ObjectID        string `json:"object_id"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	SubjectRelation string `json:"subject_relation,omitempty"`
	CreatedRev      int64  `json:"created_rev"`
	DeletedRev      *int64 `json:"deleted_rev,omitempty"`
}

func (t Tuple) String() string {
	subj := t.SubjectType + ":" + t.SubjectID
	if t.SubjectRelation != "" {
		subj += "#" + t.SubjectRelation
	}
	return fmt.Sprintf("%s:%s#%s@%s", t.ObjectType, t.ObjectID, t.Relation, subj)
}

// Validate validates all tuple components against specification constraints.
func (t *Tuple) Validate() error {
	if !ValidateTypeOrRelation(t.ObjectType) {
		return fmt.Errorf("%w: invalid object type %q", ErrInvalidIdentifier, t.ObjectType)
	}
	if !ValidateID(t.ObjectID, false) {
		return fmt.Errorf("%w: invalid object id %q", ErrInvalidIdentifier, t.ObjectID)
	}
	if !ValidateTypeOrRelation(t.Relation) {
		return fmt.Errorf("%w: invalid relation %q", ErrInvalidIdentifier, t.Relation)
	}
	if !ValidateTypeOrRelation(t.SubjectType) {
		return fmt.Errorf("%w: invalid subject type %q", ErrInvalidIdentifier, t.SubjectType)
	}
	if !ValidateID(t.SubjectID, true) {
		return fmt.Errorf("%w: invalid subject id %q", ErrInvalidIdentifier, t.SubjectID)
	}
	if t.SubjectRelation != "" && !ValidateTypeOrRelation(t.SubjectRelation) {
		return fmt.Errorf("%w: invalid subject relation %q", ErrInvalidIdentifier, t.SubjectRelation)
	}
	// Wildcard subjects cannot have subject relations
	if t.SubjectID == "*" && t.SubjectRelation != "" {
		return fmt.Errorf("%w: wildcard subject %s:* cannot have subject relation", ErrInvalidIdentifier, t.SubjectType)
	}
	return nil
}

// Operation types for WriteRelationships.
const (
	OpTouch  = "touch"
	OpCreate = "create"
	OpDelete = "delete"
)

// TupleOperation is an atomic operation within a write batch.
type TupleOperation struct {
	Op    string `json:"op"`
	Tuple Tuple  `json:"tuple"`
}

// TupleFilter specifies criteria for reading tuples.
type TupleFilter struct {
	ObjectType      string
	ObjectID        string
	Relation        string
	SubjectType     string
	SubjectID       string
	SubjectRelation *string
	Limit           int
}
