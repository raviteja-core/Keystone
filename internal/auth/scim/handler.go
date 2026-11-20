package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

// Handler implements RFC 7644 SCIM 2.0 User Management.
type Handler struct {
	baseURL string
	store   *store.Store
	logger  *slog.Logger
}

// NewHandler creates a new SCIM 2.0 Handler.
func NewHandler(baseURL string, s *store.Store, logger *slog.Logger) *Handler {
	return &Handler{
		baseURL: strings.TrimRight(baseURL, "/"),
		store:   s,
		logger:  logger,
	}
}

// RegisterRoutes registers SCIM endpoints onto a ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /scim/v2/Users", h.handleListUsers)
	mux.HandleFunc("POST /scim/v2/Users", h.handleCreateUser)
	mux.HandleFunc("GET /scim/v2/Users/{id}", h.handleGetUser)
	mux.HandleFunc("PUT /scim/v2/Users/{id}", h.handleUpdateUser)
	mux.HandleFunc("DELETE /scim/v2/Users/{id}", h.handleDeleteUser)
}

func (h *Handler) handleListUsers(w http.ResponseWriter, r *http.Request) {
	startIndex := 1
	count := 50

	if s := r.URL.Query().Get("startIndex"); s != "" {
		if val, err := strconv.Atoi(s); err == nil && val > 0 {
			startIndex = val
		}
	}
	if c := r.URL.Query().Get("count"); c != "" {
		if val, err := strconv.Atoi(c); err == nil && val >= 0 {
			count = val
		}
	}

	offset := startIndex - 1
	users, total, err := h.store.ListUsers(r.Context(), offset, count)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "failed to query users: "+err.Error(), "")
		return
	}

	resources := make([]UserResource, len(users))
	for i, u := range users {
		resources[i] = UserToSCIM(u, h.baseURL)
	}

	resp := ListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}

	h.sendJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var input UserResource
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid SCIM JSON payload: "+err.Error(), "invalidSyntax")
		return
	}

	email := input.UserName
	if len(input.Emails) > 0 && input.Emails[0].Value != "" {
		email = input.Emails[0].Value
	}

	if email == "" {
		h.sendError(w, http.StatusBadRequest, "userName or email is required", "invalidValue")
		return
	}

	uid, _ := ids.NewUUIDv7()
	status := "active"
	if !input.Active {
		status = "disabled"
	}

	var displayName *string
	if input.DisplayName != nil && *input.DisplayName != "" {
		displayName = input.DisplayName
	} else if input.Name != nil && input.Name.Formatted != "" {
		displayName = &input.Name.Formatted
	}

	u := &store.User{
		ID:           uid,
		Email:        email,
		Username:     &input.UserName,
		DisplayName:  displayName,
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$unusable$unusable", // SCIM provisioned users set password via self-service
		Status:       status,
		ExternalID:   input.ExternalID,
	}

	if err := h.store.CreateUser(r.Context(), u); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			h.sendError(w, http.StatusConflict, fmt.Sprintf("User %q already exists", email), "uniqueness")
			return
		}
		h.sendError(w, http.StatusInternalServerError, "failed to provision user: "+err.Error(), "")
		return
	}

	scimUser := UserToSCIM(u, h.baseURL)
	w.Header().Set("Location", scimUser.Meta.Location)
	h.sendJSON(w, http.StatusCreated, scimUser)
}

func (h *Handler) handleGetUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	uid, err := uuid.Parse(idStr)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "user not found", "")
		return
	}

	u, err := h.store.GetUserByID(r.Context(), uid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.sendError(w, http.StatusNotFound, "user not found", "")
			return
		}
		h.sendError(w, http.StatusInternalServerError, "failed to get user: "+err.Error(), "")
		return
	}

	h.sendJSON(w, http.StatusOK, UserToSCIM(u, h.baseURL))
}

func (h *Handler) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	uid, err := uuid.Parse(idStr)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "user not found", "")
		return
	}

	u, err := h.store.GetUserByID(r.Context(), uid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.sendError(w, http.StatusNotFound, "user not found", "")
			return
		}
		h.sendError(w, http.StatusInternalServerError, "failed to find user: "+err.Error(), "")
		return
	}

	var input UserResource
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid payload: "+err.Error(), "invalidSyntax")
		return
	}

	if len(input.Emails) > 0 && input.Emails[0].Value != "" {
		u.Email = input.Emails[0].Value
	}
	if input.UserName != "" {
		u.Username = &input.UserName
	}
	if input.DisplayName != nil {
		u.DisplayName = input.DisplayName
	}
	if input.Active {
		u.Status = "active"
	} else {
		u.Status = "disabled"
	}

	if err := h.store.UpdateUser(r.Context(), u); err != nil {
		h.sendError(w, http.StatusInternalServerError, "failed to update user: "+err.Error(), "")
		return
	}

	h.sendJSON(w, http.StatusOK, UserToSCIM(u, h.baseURL))
}

func (h *Handler) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	uid, err := uuid.Parse(idStr)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "user not found", "")
		return
	}

	if err := h.store.DeleteUser(r.Context(), uid); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			h.sendError(w, http.StatusNotFound, "user not found", "")
			return
		}
		h.sendError(w, http.StatusInternalServerError, "failed to delete user: "+err.Error(), "")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) sendJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", ContentTypeSCIM)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) sendError(w http.ResponseWriter, status int, detail string, scimType string) {
	resp := ErrorResponse{
		Schemas:  []string{ErrorSchema},
		Status:   strconv.Itoa(status),
		Detail:   detail,
		ScimType: scimType,
	}
	h.sendJSON(w, status, resp)
}
