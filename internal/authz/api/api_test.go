package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/authz/api"
	"github.com/raviteja-core/keystone/internal/authz/engine"
	"github.com/raviteja-core/keystone/internal/authz/store"
	"github.com/raviteja-core/keystone/internal/platform/db"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

type testEnv struct {
	pool      *pgxpool.Pool
	store     *store.Store
	engine    *engine.Engine
	auth      *api.Authenticator
	handler   http.Handler
	signerKey *rsa.PrivateKey
	kid       string
}

func getTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("KEYSTONE_AUTHZ_DB_URL")
	if url == "" {
		port := os.Getenv("KEYSTONE_POSTGRES_PORT")
		if port == "" {
			port = "54320"
		}
		url = "postgres://keystone_authz_app:authz_dev_password@localhost:" + port + "/keystone_authz?sslmode=disable"
	}

	ctx := context.Background()
	pool, err := db.NewPool(ctx, db.DefaultConfig(url))
	if err != nil {
		t.Fatalf("failed to connect to authz database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
	})
	return pool
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	pool := getTestPool(t)
	s := store.New(pool)
	eng := engine.New(s, engine.DefaultConfig())

	// Generate RS256 signing key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	kid := "test-key-1"

	keyProvider := api.NewStaticKeyProvider(map[string]*rsa.PublicKey{
		kid: &privKey.PublicKey,
	})

	authenticator := api.NewAuthenticator("https://auth.keystone.local", "keystone-authz", keyProvider)
	handler := api.NewServerMux(pool, s, eng, authenticator, api.DefaultServerConfig())

	return &testEnv{
		pool:      pool,
		store:     s,
		engine:    eng,
		auth:      authenticator,
		handler:   handler,
		signerKey: privKey,
		kid:       kid,
	}
}

func (env *testEnv) makeToken(t *testing.T, tenantID, clientID, scope string) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: env.signerKey},
		(&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", env.kid),
	)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	now := time.Now()
	claims := api.AuthTokenClaims{
		AccessTokenClaims: struct {
			Issuer    string   `json:"iss"`
			Subject   string   `json:"sub"`
			Audience  []string `json:"aud"`
			Expiry    int64    `json:"exp"`
			IssuedAt  int64    `json:"iat"`
			NotBefore int64    `json:"nbf"`
			ID        string   `json:"jti"`
			ClientID  string   `json:"client_id"`
			Scope     string   `json:"scope"`
			SessionID string   `json:"sid,omitempty"`
			AMR       []string `json:"amr,omitempty"`
		}{
			Issuer:    "https://auth.keystone.local",
			Subject:   "sub-" + clientID,
			Audience:  []string{"keystone-authz"},
			Expiry:    now.Add(1 * time.Hour).Unix(),
			IssuedAt:  now.Unix(),
			NotBefore: now.Add(-1 * time.Minute).Unix(),
			ID:        "jti-12345",
			ClientID:  clientID,
			Scope:     scope,
		},
		Tenant: tenantID,
	}

	rawJWT, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("failed to sign JWT: %v", err)
	}
	return rawJWT
}

const standardSchema = `
version: 1
types:
  user: {}
  group:
    relations:
      member: [user, "group#member"]
  folder:
    relations:
      parent: [folder]
      viewer: [user, "user:*"]
    permissions:
      view: "viewer + parent->view"
  doc:
    relations:
      parent: [folder]
      owner:  [user]
      editor: ["group#member"]
      banned: [user]
    permissions:
      edit: "owner + editor"
      view: "(edit + parent->view) - banned"
`

func TestAPI_SchemaLifecycleAndValidation(t *testing.T) {
	env := setupTestEnv(t)
	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_api_schema_" + strings.ReplaceAll(uid.String(), "-", "")

	adminToken := env.makeToken(t, tenantID, "admin-client", "authz:admin")
	readToken := env.makeToken(t, tenantID, "read-client", "authz:read")
	checkToken := env.makeToken(t, tenantID, "check-client", "authz:check")

	// 1. GET /v1/schema before schema configured returns 404
	req := httptest.NewRequest(http.MethodGet, "/v1/schema", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unconfigured schema, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var prob api.ProblemDetails
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if prob.Status != http.StatusNotFound {
		t.Fatalf("expected ProblemDetails status 404, got %v", prob)
	}

	// 2. PUT /v1/schema with checkToken fails with 403 Forbidden
	req = httptest.NewRequest(http.MethodPut, "/v1/schema", strings.NewReader(standardSchema))
	req.Header.Set("Authorization", "Bearer "+checkToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for checkToken on PUT /v1/schema, got %d", rec.Code)
	}

	// 3. PUT /v1/schema with invalid schema syntax/cycle fails with 400 Bad Request
	invalidSchema := `
version: 1
types:
  doc:
    permissions:
      p1: p2
      p2: p1
`
	req = httptest.NewRequest(http.MethodPut, "/v1/schema", strings.NewReader(invalidSchema))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for cyclic schema, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 4. PUT /v1/schema with valid schema creates tenant and saves version 1
	req = httptest.NewRequest(http.MethodPut, "/v1/schema", strings.NewReader(standardSchema))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for PUT /v1/schema, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var putResp api.PutSchemaResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &putResp); err != nil {
		t.Fatalf("failed to decode PUT response: %v", err)
	}
	if putResp.Version != 1 || putResp.Zookie == "" {
		t.Fatalf("unexpected PUT response: %+v", putResp)
	}

	// 5. GET /v1/schema returns active schema definition
	req = httptest.NewRequest(http.MethodGet, "/v1/schema", nil)
	req.Header.Set("Authorization", "Bearer "+readToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for GET /v1/schema, got %d", rec.Code)
	}
	var getResp api.GetSchemaResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &getResp); err != nil {
		t.Fatalf("failed to decode GET response: %v", err)
	}
	if getResp.Version != 1 || !strings.Contains(getResp.Definition, "doc:") {
		t.Fatalf("unexpected GET response: %+v", getResp)
	}
}

func TestAPI_RelationshipsWriteAndRead(t *testing.T) {
	env := setupTestEnv(t)
	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_api_rels_" + strings.ReplaceAll(uid.String(), "-", "")

	adminToken := env.makeToken(t, tenantID, "admin", "authz:admin")
	writeToken := env.makeToken(t, tenantID, "writer", "authz:write")
	readToken := env.makeToken(t, tenantID, "reader", "authz:read")
	checkToken := env.makeToken(t, tenantID, "checker", "authz:check")

	// Upload schema first
	req := httptest.NewRequest(http.MethodPut, "/v1/schema", strings.NewReader(standardSchema))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema upload failed: %d", rec.Code)
	}

	// 1. checkToken cannot write relationships (403 Forbidden)
	writeBody, _ := json.Marshal(api.WriteRelationshipsRequest{
		Updates: []api.TupleOperationDTO{
			{
				Op: "create",
				Tuple: api.TupleDTO{
					Object:   &api.ObjectRef{Type: "doc", ID: "1"},
					Relation: "owner",
					Subject:  &api.SubjectRef{Type: "user", ID: "alice"},
				},
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/relationships/write", bytes.NewReader(writeBody))
	req.Header.Set("Authorization", "Bearer "+checkToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for checkToken on write, got %d", rec.Code)
	}

	// 2. Invalid relation against schema returns 400 Bad Request
	badWriteBody, _ := json.Marshal(api.WriteRelationshipsRequest{
		Updates: []api.TupleOperationDTO{
			{
				Op: "create",
				Tuple: api.TupleDTO{
					Object:   &api.ObjectRef{Type: "doc", ID: "1"},
					Relation: "nonexistent_relation",
					Subject:  &api.SubjectRef{Type: "user", ID: "alice"},
				},
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/relationships/write", bytes.NewReader(badWriteBody))
	req.Header.Set("Authorization", "Bearer "+writeToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown relation, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 3. Valid write succeeds and returns zookie
	req = httptest.NewRequest(http.MethodPost, "/v1/relationships/write", bytes.NewReader(writeBody))
	req.Header.Set("Authorization", "Bearer "+writeToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid write, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var writeResp api.WriteRelationshipsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &writeResp)
	if writeResp.Zookie == "" {
		t.Fatalf("expected non-empty zookie in write response")
	}

	// 4. Precondition check: assert tuple exists (fails if it doesn't)
	preconditionFailBody, _ := json.Marshal(api.WriteRelationshipsRequest{
		Preconditions: []api.PreconditionDTO{
			{
				Tuple: api.TupleDTO{
					Object:   &api.ObjectRef{Type: "doc", ID: "999"},
					Relation: "owner",
					Subject:  &api.SubjectRef{Type: "user", ID: "nobody"},
				},
				Exists: true,
			},
		},
		Updates: []api.TupleOperationDTO{
			{
				Op: "touch",
				Tuple: api.TupleDTO{
					Object:   &api.ObjectRef{Type: "doc", ID: "1"},
					Relation: "owner",
					Subject:  &api.SubjectRef{Type: "user", ID: "alice"},
				},
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/relationships/write", bytes.NewReader(preconditionFailBody))
	req.Header.Set("Authorization", "Bearer "+writeToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("expected 412 Precondition Failed, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 5. Read relationships back
	readReqBody, _ := json.Marshal(api.ReadRelationshipsRequest{
		ObjectType: "doc",
		ObjectID:   "1",
		Relation:   "owner",
		Consistency: &api.ConsistencyDTO{
			Token: writeResp.Zookie,
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/relationships/read", bytes.NewReader(readReqBody))
	req.Header.Set("Authorization", "Bearer "+readToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for read, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var readResp api.ReadRelationshipsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &readResp)
	if len(readResp.Tuples) != 1 || readResp.Tuples[0].Subject.ID != "alice" {
		t.Fatalf("unexpected read response: %+v", readResp)
	}
}

func TestAPI_CheckAndBatchCheck(t *testing.T) {
	env := setupTestEnv(t)
	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_api_check_" + strings.ReplaceAll(uid.String(), "-", "")

	adminToken := env.makeToken(t, tenantID, "admin", "authz:admin")
	writeToken := env.makeToken(t, tenantID, "writer", "authz:write")
	checkToken := env.makeToken(t, tenantID, "checker", "authz:check")

	// 1. Check on uninitialized tenant returns 400 Bad Request (never allow)
	checkBody, _ := json.Marshal(api.CheckRequestDTO{
		Resource:   &api.ObjectRef{Type: "doc", ID: "1"},
		Permission: "view",
		Subject:    api.SubjectRef{Type: "user", ID: "alice"},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/check", bytes.NewReader(checkBody))
	req.Header.Set("Authorization", "Bearer "+checkToken)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
		t.Fatalf("expected 400 or 404 for check on uninitialized tenant, got %d (body: %s)", rec.Code, rec.Body.String())
	}

	// 2. Initialize schema & relations
	req = httptest.NewRequest(http.MethodPut, "/v1/schema", strings.NewReader(standardSchema))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema upload failed: %d", rec.Code)
	}

	// Write relationships:
	// - doc:1#owner@alice
	// - group:eng#member@bob
	// - doc:1#editor@group:eng#member
	// - doc:1#banned@eve
	writeBody, _ := json.Marshal(api.WriteRelationshipsRequest{
		Updates: []api.TupleOperationDTO{
			{Op: "create", Tuple: api.TupleDTO{Object: &api.ObjectRef{Type: "doc", ID: "1"}, Relation: "owner", Subject: &api.SubjectRef{Type: "user", ID: "alice"}}},
			{Op: "create", Tuple: api.TupleDTO{Object: &api.ObjectRef{Type: "group", ID: "eng"}, Relation: "member", Subject: &api.SubjectRef{Type: "user", ID: "bob"}}},
			{Op: "create", Tuple: api.TupleDTO{Object: &api.ObjectRef{Type: "doc", ID: "1"}, Relation: "editor", Subject: &api.SubjectRef{Type: "group", ID: "eng", Relation: "member"}}},
			{Op: "create", Tuple: api.TupleDTO{Object: &api.ObjectRef{Type: "doc", ID: "1"}, Relation: "banned", Subject: &api.SubjectRef{Type: "user", ID: "eve"}}},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/relationships/write", bytes.NewReader(writeBody))
	req.Header.Set("Authorization", "Bearer "+writeToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("write failed: %d (body: %s)", rec.Code, rec.Body.String())
	}
	var writeResp api.WriteRelationshipsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &writeResp)

	// 3. Single Check: Alice is owner -> view ALLOWED
	req = httptest.NewRequest(http.MethodPost, "/v1/check", bytes.NewReader(checkBody))
	req.Header.Set("Authorization", "Bearer "+checkToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("check failed: %d (body: %s)", rec.Code, rec.Body.String())
	}
	var checkResp api.CheckResponseDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &checkResp)
	if !checkResp.Allowed {
		t.Fatalf("expected alice to be ALLOWED")
	}

	// 4. Batch Check (Alice, Bob, Eve, UnknownUser)
	batchBody, _ := json.Marshal(api.BatchCheckRequestDTO{
		Consistency: &api.ConsistencyDTO{Token: writeResp.Zookie},
		Checks: []api.CheckRequestDTO{
			{Resource: &api.ObjectRef{Type: "doc", ID: "1"}, Permission: "view", Subject: api.SubjectRef{Type: "user", ID: "alice"}},
			{Resource: &api.ObjectRef{Type: "doc", ID: "1"}, Permission: "edit", Subject: api.SubjectRef{Type: "user", ID: "bob"}},
			{Resource: &api.ObjectRef{Type: "doc", ID: "1"}, Permission: "view", Subject: api.SubjectRef{Type: "user", ID: "eve"}},
			{Resource: &api.ObjectRef{Type: "doc", ID: "1"}, Permission: "view", Subject: api.SubjectRef{Type: "user", ID: "stranger"}},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/check/batch", bytes.NewReader(batchBody))
	req.Header.Set("Authorization", "Bearer "+checkToken)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("batch check failed: %d (body: %s)", rec.Code, rec.Body.String())
	}
	var batchResp api.BatchCheckResponseDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &batchResp)

	if len(batchResp.Results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(batchResp.Results))
	}
	if !batchResp.Results[0].Allowed { // Alice view -> true
		t.Errorf("expected alice to be ALLOWED")
	}
	if !batchResp.Results[1].Allowed { // Bob edit -> true
		t.Errorf("expected bob to be ALLOWED")
	}
	if batchResp.Results[2].Allowed { // Eve view -> false (banned)
		t.Errorf("expected eve to be DENIED")
	}
	if batchResp.Results[3].Allowed { // Stranger view -> false
		t.Errorf("expected stranger to be DENIED")
	}
}

func TestAPI_TenantIsolationAndZookieValidation(t *testing.T) {
	env := setupTestEnv(t)
	uidA, _ := ids.NewUUIDv7()
	tenantA := "tenant_api_iso_a_" + strings.ReplaceAll(uidA.String(), "-", "")
	uidB, _ := ids.NewUUIDv7()
	tenantB := "tenant_api_iso_b_" + strings.ReplaceAll(uidB.String(), "-", "")

	tokenA := env.makeToken(t, tenantA, "client-a", "authz:admin authz:write authz:read authz:check")
	tokenB := env.makeToken(t, tenantB, "client-b", "authz:admin authz:write authz:read authz:check")

	// 1. Initialize Tenant A
	req := httptest.NewRequest(http.MethodPut, "/v1/schema", strings.NewReader(standardSchema))
	req.Header.Set("Authorization", "Bearer "+tokenA)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant A schema upload failed: %d", rec.Code)
	}

	writeA, _ := json.Marshal(api.WriteRelationshipsRequest{
		Updates: []api.TupleOperationDTO{
			{Op: "create", Tuple: api.TupleDTO{Object: &api.ObjectRef{Type: "doc", ID: "secret_a"}, Relation: "owner", Subject: &api.SubjectRef{Type: "user", ID: "alice"}}},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/relationships/write", bytes.NewReader(writeA))
	req.Header.Set("Authorization", "Bearer "+tokenA)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	var respA api.WriteRelationshipsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &respA)

	// 2. Initialize Tenant B
	req = httptest.NewRequest(http.MethodPut, "/v1/schema", strings.NewReader(standardSchema))
	req.Header.Set("Authorization", "Bearer "+tokenB)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("tenant B schema upload failed: %d", rec.Code)
	}

	// 3. Tenant B attempts to use Tenant A's zookie -> rejected with 400 Bad Request
	crossCheck, _ := json.Marshal(api.CheckRequestDTO{
		Resource:   &api.ObjectRef{Type: "doc", ID: "secret_a"},
		Permission: "view",
		Subject:    api.SubjectRef{Type: "user", ID: "alice"},
		Consistency: &api.ConsistencyDTO{
			Token: respA.Zookie, // Zookie issued to Tenant A
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/check", bytes.NewReader(crossCheck))
	req.Header.Set("Authorization", "Bearer "+tokenB) // Authenticated as Tenant B
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for cross-tenant zookie, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var prob api.ProblemDetails
	_ = json.Unmarshal(rec.Body.Bytes(), &prob)
	if !strings.Contains(strings.ToLower(prob.Detail), "tenant") {
		t.Fatalf("expected problem detail mentioning tenant mismatch, got: %v", prob)
	}

	// 4. Tenant B cannot see Tenant A's tuples in relationships/read
	readB, _ := json.Marshal(api.ReadRelationshipsRequest{
		ObjectType: "doc",
		ObjectID:   "secret_a",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/relationships/read", bytes.NewReader(readB))
	req.Header.Set("Authorization", "Bearer "+tokenB)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for Tenant B read, got %d", rec.Code)
	}
	var readRespB api.ReadRelationshipsResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &readRespB)
	if len(readRespB.Tuples) != 0 {
		t.Fatalf("TENANT ISOLATION BREACH: Tenant B saw %d tuples of Tenant A: %+v", len(readRespB.Tuples), readRespB.Tuples)
	}

	// 5. Tenant B checks secret_a on Tenant B -> DENIED (not in Tenant B's data)
	checkB, _ := json.Marshal(api.CheckRequestDTO{
		Resource:   &api.ObjectRef{Type: "doc", ID: "secret_a"},
		Permission: "view",
		Subject:    api.SubjectRef{Type: "user", ID: "alice"},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/check", bytes.NewReader(checkB))
	req.Header.Set("Authorization", "Bearer "+tokenB)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for check, got %d", rec.Code)
	}
	var checkRespB api.CheckResponseDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &checkRespB)
	if checkRespB.Allowed {
		t.Fatalf("TENANT ISOLATION BREACH: Tenant B allowed access to Tenant A's resource")
	}
}

func TestAPI_ExpandPermission(t *testing.T) {
	env := setupTestEnv(t)
	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_api_expand_" + strings.ReplaceAll(uid.String(), "-", "")

	token := env.makeToken(t, tenantID, "client", "authz:admin authz:write authz:read")

	// Initialize schema & relation
	req := httptest.NewRequest(http.MethodPut, "/v1/schema", strings.NewReader(standardSchema))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema upload failed: %d", rec.Code)
	}

	write, _ := json.Marshal(api.WriteRelationshipsRequest{
		Updates: []api.TupleOperationDTO{
			{Op: "create", Tuple: api.TupleDTO{Object: &api.ObjectRef{Type: "doc", ID: "1"}, Relation: "owner", Subject: &api.SubjectRef{Type: "user", ID: "alice"}}},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/relationships/write", bytes.NewReader(write))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("write failed: %d", rec.Code)
	}

	// POST /v1/expand
	expandBody, _ := json.Marshal(api.ExpandRequestDTO{
		Resource:   &api.ObjectRef{Type: "doc", ID: "1"},
		Permission: "edit",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/expand", bytes.NewReader(expandBody))
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	env.handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for expand, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	var expandResp api.ExpandResponseDTO
	_ = json.Unmarshal(rec.Body.Bytes(), &expandResp)

	if expandResp.Tree == nil || expandResp.Tree.Type != "union" {
		t.Fatalf("unexpected expand tree: %+v", expandResp.Tree)
	}
}
