package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidZookie        = errors.New("invalid zookie token")
	ErrZookieTenantMismatch = errors.New("zookie tenant does not match caller tenant")
)

// Zookie represents a Zanzibar snapshot revision token.
type Zookie struct {
	Tenant   string `json:"t"`
	Revision int64  `json:"r"`
}

// EncodeZookie encodes tenant and revision into an opaque "v1." base64url string.
func EncodeZookie(tenant string, revision int64) string {
	payload, _ := json.Marshal(Zookie{
		Tenant:   tenant,
		Revision: revision,
	})
	return "v1." + base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeZookie parses and validates a zookie string.
func DecodeZookie(raw string) (Zookie, error) {
	if !strings.HasPrefix(raw, "v1.") {
		return Zookie{}, fmt.Errorf("%w: missing v1. prefix", ErrInvalidZookie)
	}

	encoded := strings.TrimPrefix(raw, "v1.")
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Zookie{}, fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidZookie, err)
	}

	var z Zookie
	if err := json.Unmarshal(data, &z); err != nil {
		return Zookie{}, fmt.Errorf("%w: invalid JSON payload: %v", ErrInvalidZookie, err)
	}

	if z.Tenant == "" {
		return Zookie{}, fmt.Errorf("%w: tenant cannot be empty", ErrInvalidZookie)
	}
	if z.Revision < 0 {
		return Zookie{}, fmt.Errorf("%w: revision cannot be negative", ErrInvalidZookie)
	}

	return z, nil
}
