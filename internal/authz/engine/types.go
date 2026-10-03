package engine

import (
	"errors"
	"fmt"

	"github.com/raviteja-core/keystone/internal/authz/store"
)

var (
	ErrDepthExceeded               = errors.New("check evaluation depth exceeded limit")
	ErrUnknownType                 = errors.New("unknown object type")
	ErrUnknownRelationOrPermission = errors.New("unknown relation or permission")
	ErrInvalidSubject              = errors.New("invalid subject")
	ErrCycleCutoffInSubtrahend     = errors.New("exclusion subtrahend hit cycle cut-off")
	ErrResourceExhausted           = errors.New("resource limit exceeded during check evaluation")
	ErrMaxDBReadsExceeded          = fmt.Errorf("%w: max db reads limit exceeded", ErrResourceExhausted)
	ErrMaxRowsPerReadExceeded      = fmt.Errorf("%w: max rows per read limit exceeded", ErrResourceExhausted)
	ErrMaxVisitedNodesExceeded     = fmt.Errorf("%w: max visited nodes limit exceeded", ErrResourceExhausted)
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
