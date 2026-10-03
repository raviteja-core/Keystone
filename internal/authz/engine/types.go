package engine

import (
	"errors"

	"github.com/raviteja-core/keystone/internal/authz/store"
)

var (
	ErrDepthExceeded               = errors.New("check evaluation depth exceeded limit")
	ErrUnknownType                 = errors.New("unknown object type")
	ErrUnknownRelationOrPermission = errors.New("unknown relation or permission")
	ErrInvalidSubject              = errors.New("invalid subject")
)

// CheckRequest encapsulates the parameters for an authorization check.
type CheckRequest struct {
	TenantID   string
	Revision   int64
	Object     store.Object
	Permission string
	Subject    store.Subject
}

// CheckResponse contains the decision and evaluation statistics.
type CheckResponse struct {
	Allowed  bool
	Revision int64
	Depth    int
	DBReads  int
}
