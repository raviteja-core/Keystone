package scim

import (
	"time"

	"github.com/google/uuid"
	"github.com/raviteja-core/keystone/internal/auth/store"
)

const (
	UserSchemaCore     = "urn:ietf:params:scim:schemas:core:2.0:User"
	ListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	ErrorSchema        = "urn:ietf:params:scim:api:messages:2.0:Error"

	ContentTypeSCIM = "application/scim+json; charset=utf-8"
)

// UserResource represents an RFC 7643 SCIM User.
type UserResource struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  *string  `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	DisplayName *string  `json:"displayName,omitempty"`
	Name        *Name    `json:"name,omitempty"`
	Emails      []Email  `json:"emails,omitempty"`
	Active      bool     `json:"active"`
	Meta        Meta     `json:"meta"`
}

type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
}

type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type Meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
	Version      string    `json:"version,omitempty"`
}

// ListResponse represents an RFC 7644 §3.4.2 search/list response.
type ListResponse struct {
	Schemas      []string       `json:"schemas"`
	TotalResults int            `json:"totalResults"`
	StartIndex   int            `json:"startIndex"`
	ItemsPerPage int            `json:"itemsPerPage"`
	Resources    []UserResource `json:"Resources"`
}

// ErrorResponse represents an RFC 7644 §3.12 error response.
type ErrorResponse struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail"`
	ScimType string   `json:"scimType,omitempty"`
}

// UserToSCIM converts an internal store.User to a SCIM UserResource.
func UserToSCIM(u *store.User, baseURL string) UserResource {
	active := u.Status == "active"
	username := u.Email
	if u.Username != nil && *u.Username != "" {
		username = *u.Username
	}

	res := UserResource{
		Schemas:     []string{UserSchemaCore},
		ID:          u.ID.String(),
		ExternalID:  u.ExternalID,
		UserName:    username,
		DisplayName: u.DisplayName,
		Active:      active,
		Emails: []Email{
			{
				Value:   u.Email,
				Type:    "work",
				Primary: true,
			},
		},
		Meta: Meta{
			ResourceType: "User",
			Created:      u.CreatedAt,
			LastModified: u.UpdatedAt,
			Location:     baseURL + "/scim/v2/Users/" + u.ID.String(),
			Version:      uuid.NewSHA1(uuid.NameSpaceOID, []byte(u.UpdatedAt.String())).String(),
		},
	}

	if u.DisplayName != nil && *u.DisplayName != "" {
		res.Name = &Name{
			Formatted: *u.DisplayName,
		}
	}

	return res
}
