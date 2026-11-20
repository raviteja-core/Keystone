package keystone

import "errors"

var (
	// Token validation errors
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token is expired")
	ErrTokenNotYetValid   = errors.New("token is not yet valid")
	ErrInvalidIssuer      = errors.New("invalid token issuer")
	ErrInvalidAudience    = errors.New("invalid token audience")
	ErrInvalidAlgorithm   = errors.New("unsupported algorithm: only RS256 is permitted")
	ErrInvalidTokenType   = errors.New("invalid token type: expected at+jwt")
	ErrSigningKeyNotFound = errors.New("signing key not found")
	ErrMissingJOSEHeader  = errors.New("missing JOSE header")
	ErrMissingKeyID       = errors.New("missing kid in token header")

	// Authorization errors
	ErrPermissionDenied        = errors.New("permission denied")
	ErrAuthzServiceUnavailable = errors.New("authorization service unavailable")
	ErrSubjectMissing          = errors.New("subject could not be resolved")
	ErrMissingObject           = errors.New("object/resource is required")
	ErrMissingPermission       = errors.New("permission is required")
)
