package scim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/auth/scim"
	"github.com/raviteja-core/keystone/internal/auth/store"
	"github.com/raviteja-core/keystone/internal/platform/db"
)

func getTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("KEYSTONE_DB_URL")
	if dbURL == "" {
		port := os.Getenv("KEYSTONE_POSTGRES_PORT")
		if port == "" {
			port = "54320"
		}
		dbURL = "postgres://keystone_auth_app:auth_dev_password@localhost:" + port + "/keystone_auth?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pool, err := db.NewPool(ctx, db.DefaultConfig(dbURL))
	if err != nil {
		t.Skipf("skipping SCIM test: PostgreSQL not available: %v", err)
	}

	return pool
}

func TestSCIM_UserLifecycle(t *testing.T) {
	pool := getTestPool(t)
	authStore := store.New(pool)
	scimHandler := scim.NewHandler("http://localhost:8080", authStore, nil)

	mux := http.NewServeMux()
	scimHandler.RegisterRoutes(mux)

	// 1. Provision User (POST /scim/v2/Users)
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "scim_user_` + time.Now().Format("150405.000") + `@example.com",
		"name": {
			"formatted": "SCIM Provisioned User"
		},
		"emails": [
			{"value": "scim_user_` + time.Now().Format("150405.000") + `@example.com", "primary": true}
		],
		"active": true
	}`

	reqCreate := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewBufferString(createBody))
	reqCreate.Header.Set("Content-Type", scim.ContentTypeSCIM)
	recCreate := httptest.NewRecorder()
	mux.ServeHTTP(recCreate, reqCreate)

	if recCreate.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d: %s", recCreate.Code, recCreate.Body.String())
	}

	var createdUser scim.UserResource
	if err := json.Unmarshal(recCreate.Body.Bytes(), &createdUser); err != nil {
		t.Fatalf("failed to decode created SCIM user: %v", err)
	}
	if createdUser.ID == "" {
		t.Fatal("expected non-empty SCIM user ID")
	}

	// 2. Retrieve User (GET /scim/v2/Users/{id})
	reqGet := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/"+createdUser.ID, nil)
	recGet := httptest.NewRecorder()
	mux.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recGet.Code)
	}

	// 3. List Users (GET /scim/v2/Users)
	reqList := httptest.NewRequest(http.MethodGet, "/scim/v2/Users?startIndex=1&count=10", nil)
	recList := httptest.NewRecorder()
	mux.ServeHTTP(recList, reqList)

	if recList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for list, got %d", recList.Code)
	}

	var listResp scim.ListResponse
	if err := json.Unmarshal(recList.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to parse SCIM list response: %v", err)
	}
	if listResp.TotalResults < 1 {
		t.Errorf("expected at least 1 user, got %d", listResp.TotalResults)
	}

	// 4. Delete User (DELETE /scim/v2/Users/{id})
	reqDel := httptest.NewRequest(http.MethodDelete, "/scim/v2/Users/"+createdUser.ID, nil)
	recDel := httptest.NewRecorder()
	mux.ServeHTTP(recDel, reqDel)

	if recDel.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for delete, got %d", recDel.Code)
	}
}
