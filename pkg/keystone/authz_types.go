package keystone

import "fmt"

// Consistency modes supported by the Keystone Authz Engine.
const (
	ConsistencyModeAtLeastAsFresh  = "at_least_as_fresh"
	ConsistencyModeFullyConsistent = "fully_consistent"
	ConsistencyModeMinimizeLatency = "minimize_latency"
)

// Consistency specifies snapshot reading requirements for authorization checks.
type Consistency struct {
	Mode  string `json:"mode,omitempty"`
	Token string `json:"token,omitempty"` // Zookie revision token
}

// AtLeastAsFresh returns a Consistency specifying that checks must observe at least the revision of zookie.
func AtLeastAsFresh(zookie string) *Consistency {
	return &Consistency{
		Mode:  ConsistencyModeAtLeastAsFresh,
		Token: zookie,
	}
}

// FullyConsistent returns a Consistency requiring the latest committed revision.
func FullyConsistent() *Consistency {
	return &Consistency{
		Mode: ConsistencyModeFullyConsistent,
	}
}

// MinimizeLatency returns a Consistency allowing reads from local cache or replica snapshots.
func MinimizeLatency() *Consistency {
	return &Consistency{
		Mode: ConsistencyModeMinimizeLatency,
	}
}

// ObjectRef identifies an entity in the authorization graph.
type ObjectRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// SubjectRef identifies an actor or userset in the authorization graph.
type SubjectRef struct {
	Type     string `json:"type"`
	ID       string `json:"id"`
	Relation string `json:"relation,omitempty"`
}

// UserSubject creates a concrete user SubjectRef.
func UserSubject(userID string) SubjectRef {
	return SubjectRef{
		Type: "user",
		ID:   userID,
	}
}

// UsersetSubject creates a userset SubjectRef (e.g. group:engineering#member).
func UsersetSubject(objectType, objectID, relation string) SubjectRef {
	return SubjectRef{
		Type:     objectType,
		ID:       objectID,
		Relation: relation,
	}
}

// WildcardSubject creates a wildcard subject for all users of a type (e.g. user:*).
func WildcardSubject(subjectType string) SubjectRef {
	return SubjectRef{
		Type: subjectType,
		ID:   "*",
	}
}

// Evaluation contains metrics regarding an authorization check.
type Evaluation struct {
	Depth   int `json:"depth"`
	DBReads int `json:"db_reads"`
}

// CheckRequest represents a permission check query.
type CheckRequest struct {
	Object      ObjectRef    `json:"object"`
	Permission  string       `json:"permission"`
	Subject     SubjectRef   `json:"subject"`
	Consistency *Consistency `json:"consistency,omitempty"`
}

// CheckResponse represents the result of an authorization check.
type CheckResponse struct {
	Allowed    bool       `json:"allowed"`
	CheckedAt  string     `json:"checked_at"`
	Evaluation Evaluation `json:"evaluation"`
}

// BatchCheckRequest represents a batch of permission checks.
type BatchCheckRequest struct {
	Checks      []CheckRequest `json:"checks"`
	Consistency *Consistency   `json:"consistency,omitempty"`
}

// BatchCheckItemResult represents an individual check result in a batch.
type BatchCheckItemResult struct {
	Allowed    bool        `json:"allowed"`
	Evaluation *Evaluation `json:"evaluation,omitempty"`
	Error      string      `json:"error,omitempty"`
}

// BatchCheckResponse represents the response of a batch check query.
type BatchCheckResponse struct {
	CheckedAt string                 `json:"checked_at"`
	Results   []BatchCheckItemResult `json:"results"`
}

// Tuple represents a single relationship tuple.
type Tuple struct {
	ObjectType      string `json:"object_type"`
	ObjectID        string `json:"object_id"`
	Relation        string `json:"relation"`
	SubjectType     string `json:"subject_type"`
	SubjectID       string `json:"subject_id"`
	SubjectRelation string `json:"subject_relation,omitempty"`
}

// TupleOperation represents an update operation on a relationship tuple.
type TupleOperation struct {
	Op    string `json:"op"` // "create", "touch", or "delete"
	Tuple Tuple  `json:"tuple"`
}

// Precondition represents a state check required before applying write operations.
type Precondition struct {
	Tuple  Tuple `json:"tuple"`
	Exists bool  `json:"exists"`
}

// WriteRelationshipsRequest represents a request to mutate relationships.
type WriteRelationshipsRequest struct {
	Operations    []TupleOperation `json:"operations"`
	Preconditions []Precondition   `json:"preconditions,omitempty"`
}

// WriteRelationshipsResponse contains the resulting consistency Zookie after writes.
type WriteRelationshipsResponse struct {
	Zookie string `json:"zookie"`
}

// ReadRelationshipsRequest queries existing relationship tuples.
type ReadRelationshipsRequest struct {
	ObjectType        string       `json:"object_type,omitempty"`
	ObjectID          string       `json:"object_id,omitempty"`
	Relation          string       `json:"relation,omitempty"`
	SubjectType       string       `json:"subject_type,omitempty"`
	SubjectID         string       `json:"subject_id,omitempty"`
	SubjectRelation   string       `json:"subject_relation,omitempty"`
	Limit             int          `json:"limit,omitempty"`
	ContinuationToken string       `json:"continuation_token,omitempty"`
	Consistency       *Consistency `json:"consistency,omitempty"`
}

// ReadRelationshipsResponse contains matching relationship tuples.
type ReadRelationshipsResponse struct {
	Tuples            []Tuple `json:"tuples"`
	ReadAt            string  `json:"read_at"`
	ContinuationToken string  `json:"continuation_token,omitempty"`
}

// ExpandRequest queries the userset tree for an object permission.
type ExpandRequest struct {
	Object      ObjectRef    `json:"object"`
	Permission  string       `json:"permission"`
	Consistency *Consistency `json:"consistency,omitempty"`
}

// ExpandTreeNode represents a node in an expanded userset tree.
type ExpandTreeNode struct {
	Type     string            `json:"type"` // "leaf", "union", "intersection", "exclusion"
	Target   *ObjectRef        `json:"target,omitempty"`
	Relation string            `json:"relation,omitempty"`
	Subject  *SubjectRef       `json:"subject,omitempty"`
	Children []*ExpandTreeNode `json:"children,omitempty"`
}

// ExpandResponse represents the expanded permission tree.
type ExpandResponse struct {
	Tree *ExpandTreeNode `json:"tree"`
}

// ProblemDetails represents an RFC 9457 HTTP Problem Details error.
type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail"`
	Instance string `json:"instance,omitempty"`
}

func (p *ProblemDetails) Error() string {
	if p.Detail != "" {
		return fmt.Sprintf("keystone error (%d %s): %s", p.Status, p.Title, p.Detail)
	}
	return fmt.Sprintf("keystone error (%d %s)", p.Status, p.Title)
}
