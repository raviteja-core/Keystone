package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/authz/schema"
	"github.com/raviteja-core/keystone/internal/authz/store"
	"github.com/raviteja-core/keystone/internal/platform/db"
	"github.com/raviteja-core/keystone/internal/platform/ids"
)

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

const testDocSchema = `
version: 1
types:
  user: {}
  group:
    relations:
      member: [user]
  folder:
    relations:
      parent: [folder]
      owner:  [user]
      editor: [user, "group#member"]
      viewer: [user, "group#member", "user:*"]
    permissions:
      view: "viewer + owner"
  doc:
    relations:
      parent: [folder]
      owner:  [user]
      editor: [user, "group#member"]
      viewer: [user, "group#member", "user:*"]
      banned: [user]
    permissions:
      edit: "owner + editor + parent->view"
      view: "edit + viewer - banned"
`

func setupTenantWithSchema(t *testing.T, s *store.Store, tenantID string) *schema.Schema {
	t.Helper()
	ctx := context.Background()

	sch, err := schema.ParseAndValidate(testDocSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}

	_, err = s.SaveSchema(ctx, tenantID, 1, testDocSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}
	return sch
}

func TestZookie_EncodeDecodeAndValidation(t *testing.T) {
	tenant := "tenant_abc"
	var rev int64 = 42

	token := store.EncodeZookie(tenant, rev)
	if token == "" {
		t.Fatal("expected non-empty zookie")
	}

	z, err := store.DecodeZookie(token)
	if err != nil {
		t.Fatalf("failed to decode zookie: %v", err)
	}
	if z.Tenant != tenant {
		t.Errorf("expected tenant %q, got %q", tenant, z.Tenant)
	}
	if z.Revision != rev {
		t.Errorf("expected revision %d, got %d", rev, z.Revision)
	}

	// Invalid tokens
	invalidTokens := []string{
		"",
		"invalid",
		"v2.badprefix",
		"v1.not-base64-json@@",
		"v1.e30", // empty json {}
	}
	for _, it := range invalidTokens {
		_, err := store.DecodeZookie(it)
		if err == nil {
			t.Errorf("expected error decoding %q, got nil", it)
		}
	}
}

func TestStore_IdentifierValidationAndSQLi(t *testing.T) {
	sqliPayloads := []string{
		"doc'; DROP TABLE authz_tuples; --",
		"admin' OR 1=1 --",
		"<script>alert(1)</script>",
		"type\x00null",
		"type\nnewline",
		stringsRepeat("a", 150),
	}

	for _, payload := range sqliPayloads {
		if store.ValidateTypeOrRelation(payload) {
			t.Errorf("expected ValidateTypeOrRelation to reject SQLi payload %q", payload)
		}
		if store.ValidateID(payload, false) {
			t.Errorf("expected ValidateID to reject SQLi payload %q", payload)
		}
	}
}

func stringsRepeat(s string, count int) string {
	var res string
	for i := 0; i < count; i++ {
		res += s
	}
	return res
}

func TestStore_SchemaCRUDAndTenantNotFound(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_" + strings.ReplaceAll(uid.String(), "-", "")

	// Non-existent tenant has no revision
	_, err := s.GetTenantRevision(ctx, tenantID)
	if !errors.Is(err, store.ErrTenantNotFound) {
		t.Fatalf("expected ErrTenantNotFound, got %v", err)
	}

	// Non-existent tenant has no schema
	_, _, err = s.GetLatestSchema(ctx, tenantID)
	if !errors.Is(err, store.ErrNoSchema) {
		t.Fatalf("expected ErrNoSchema, got %v", err)
	}

	// Saving schema creates tenant and initializes revision to 1
	sch, _ := schema.ParseAndValidate(testDocSchema)
	rev, err := s.SaveSchema(ctx, tenantID, 1, testDocSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}
	if rev != 1 {
		t.Fatalf("expected initial revision 1, got %d", rev)
	}

	// Tenant revision matches
	currentRev, err := s.GetTenantRevision(ctx, tenantID)
	if err != nil {
		t.Fatalf("failed to get tenant revision: %v", err)
	}
	if currentRev != 1 {
		t.Fatalf("expected current_rev 1, got %d", currentRev)
	}

	// Retrieve schema
	fetchedSch, ver, err := s.GetLatestSchema(ctx, tenantID)
	if err != nil {
		t.Fatalf("failed to get latest schema: %v", err)
	}
	if ver != 1 {
		t.Errorf("expected version 1, got %d", ver)
	}
	if len(fetchedSch.Types) != len(sch.Types) {
		t.Errorf("expected %d types, got %d", len(sch.Types), len(fetchedSch.Types))
	}
}

func TestStore_WriteValidationAgainstSchema(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_" + strings.ReplaceAll(uid.String(), "-", "")
	setupTenantWithSchema(t, s, tenantID)

	tests := []struct {
		name        string
		tuple       store.Tuple
		shouldFail  bool
		errContains string
	}{
		{
			name: "valid direct owner",
			tuple: store.Tuple{
				ObjectType:  "doc",
				ObjectID:    "doc1",
				Relation:    "owner",
				SubjectType: "user",
				SubjectID:   "alice",
			},
			shouldFail: false,
		},
		{
			name: "valid wildcard viewer",
			tuple: store.Tuple{
				ObjectType:  "doc",
				ObjectID:    "doc1",
				Relation:    "viewer",
				SubjectType: "user",
				SubjectID:   "*",
			},
			shouldFail: false,
		},
		{
			name: "valid userset editor",
			tuple: store.Tuple{
				ObjectType:      "doc",
				ObjectID:        "doc1",
				Relation:        "editor",
				SubjectType:     "group",
				SubjectID:       "eng",
				SubjectRelation: "member",
			},
			shouldFail: false,
		},
		{
			name: "unknown object type",
			tuple: store.Tuple{
				ObjectType:  "unknown_obj",
				ObjectID:    "x",
				Relation:    "owner",
				SubjectType: "user",
				SubjectID:   "alice",
			},
			shouldFail:  true,
			errContains: "unknown object type",
		},
		{
			name: "unknown relation",
			tuple: store.Tuple{
				ObjectType:  "doc",
				ObjectID:    "doc1",
				Relation:    "nonexistent_rel",
				SubjectType: "user",
				SubjectID:   "alice",
			},
			shouldFail:  true,
			errContains: "unknown relation",
		},
		{
			name: "wildcard where not allowed",
			tuple: store.Tuple{
				ObjectType:  "doc",
				ObjectID:    "doc1",
				Relation:    "owner",
				SubjectType: "user",
				SubjectID:   "*",
			},
			shouldFail:  true,
			errContains: "not an allowed subject type",
		},
		{
			name: "subject relation does not exist on subject type",
			tuple: store.Tuple{
				ObjectType:      "doc",
				ObjectID:        "doc1",
				Relation:        "editor",
				SubjectType:     "group",
				SubjectID:       "eng",
				SubjectRelation: "nonexistent_sub_rel",
			},
			shouldFail:  true,
			errContains: "not an allowed subject type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
				{Op: store.OpCreate, Tuple: tt.tuple},
			})
			if tt.shouldFail {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tt.name)
				}
				if !errors.Is(err, store.ErrSchemaValidation) {
					t.Errorf("expected ErrSchemaValidation, got %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected write error for %s: %v", tt.name, err)
				}
			}
		})
	}
}

func TestStore_CreateTouchDeleteAndBatchSemantics(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_" + strings.ReplaceAll(uid.String(), "-", "")
	setupTenantWithSchema(t, s, tenantID)

	tupleA := store.Tuple{
		ObjectType:  "doc",
		ObjectID:    "101",
		Relation:    "owner",
		SubjectType: "user",
		SubjectID:   "alice",
	}

	// 1. Create succeeds
	rev1, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: tupleA},
	})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	// 2. Second Create of same live tuple fails with ErrTupleAlreadyExists
	_, err = s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: tupleA},
	})
	if !errors.Is(err, store.ErrTupleAlreadyExists) {
		t.Fatalf("expected ErrTupleAlreadyExists, got %v", err)
	}

	// 3. Touch of existing live tuple is a no-op returning a valid zookie
	revTouch, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpTouch, Tuple: tupleA},
	})
	if err != nil {
		t.Fatalf("touch of existing tuple should succeed, got: %v", err)
	}
	if revTouch <= rev1 {
		t.Fatalf("expected strictly increasing rev for touch, got %d <= %d", revTouch, rev1)
	}

	// 4. Delete of non-existent tuple is idempotent (succeeds)
	tupleNonExistent := store.Tuple{
		ObjectType:  "doc",
		ObjectID:    "999",
		Relation:    "owner",
		SubjectType: "user",
		SubjectID:   "bob",
	}
	revDelNonExistent, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpDelete, Tuple: tupleNonExistent},
	})
	if err != nil {
		t.Fatalf("delete of non-existent tuple should succeed, got: %v", err)
	}
	if revDelNonExistent <= revTouch {
		t.Fatalf("expected increasing rev, got %d <= %d", revDelNonExistent, revTouch)
	}

	// 5. Create + Delete of the same tuple in ONE batch
	tupleB := store.Tuple{
		ObjectType:  "doc",
		ObjectID:    "202",
		Relation:    "owner",
		SubjectType: "user",
		SubjectID:   "bob",
	}
	revBatch, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: tupleB},
		{Op: store.OpDelete, Tuple: tupleB},
	})
	if err != nil {
		t.Fatalf("create+delete in same batch failed: %v", err)
	}

	// Verify tupleB is NOT live at revBatch
	tuples, err := s.ReadTuples(ctx, tenantID, store.TupleFilter{ObjectID: "202"}, revBatch)
	if err != nil {
		t.Fatalf("failed to read tuples: %v", err)
	}
	if len(tuples) != 0 {
		t.Fatalf("expected tupleB to be deleted, got %d tuples", len(tuples))
	}
}

func TestStore_SnapshotReads(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_" + strings.ReplaceAll(uid.String(), "-", "")
	setupTenantWithSchema(t, s, tenantID)

	tuple := store.Tuple{
		ObjectType:  "doc",
		ObjectID:    "303",
		Relation:    "owner",
		SubjectType: "user",
		SubjectID:   "alice",
	}

	// Before write (rev 1 = schema)
	readRev1, err := s.ReadTuples(ctx, tenantID, store.TupleFilter{ObjectID: "303"}, 1)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if len(readRev1) != 0 {
		t.Fatalf("expected 0 tuples before write, got %d", len(readRev1))
	}

	// Write at rev 2
	rev2, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: tuple},
	})
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Delete at rev 3
	rev3, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpDelete, Tuple: tuple},
	})
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	// Read at snapshot rev 1: 0 tuples
	r1, _ := s.ReadTuples(ctx, tenantID, store.TupleFilter{ObjectID: "303"}, 1)
	if len(r1) != 0 {
		t.Errorf("snapshot at rev 1 should have 0 tuples, got %d", len(r1))
	}

	// Read at snapshot rev 2: 1 tuple visible!
	r2, _ := s.ReadTuples(ctx, tenantID, store.TupleFilter{ObjectID: "303"}, rev2)
	if len(r2) != 1 {
		t.Errorf("snapshot at rev 2 should have 1 tuple, got %d", len(r2))
	}

	// Read at snapshot rev 3: 0 tuples (deleted at rev 3)
	r3, _ := s.ReadTuples(ctx, tenantID, store.TupleFilter{ObjectID: "303"}, rev3)
	if len(r3) != 0 {
		t.Errorf("snapshot at rev 3 should have 0 tuples, got %d", len(r3))
	}
}

func TestStore_TenantIsolation(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uA, _ := ids.NewUUIDv7()
	uB, _ := ids.NewUUIDv7()
	tenantA := "tenant_" + strings.ReplaceAll(uA.String(), "-", "")
	tenantB := "tenant_" + strings.ReplaceAll(uB.String(), "-", "")

	setupTenantWithSchema(t, s, tenantA)
	setupTenantWithSchema(t, s, tenantB)

	tupleA := store.Tuple{
		ObjectType:  "doc",
		ObjectID:    "secret_doc",
		Relation:    "owner",
		SubjectType: "user",
		SubjectID:   "alice",
	}

	revA, err := s.WriteRelationships(ctx, tenantA, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: tupleA},
	})
	if err != nil {
		t.Fatalf("failed to write tenantA tuple: %v", err)
	}

	// Tenant B reads with same object ID at its own revision
	revB, _ := s.GetTenantRevision(ctx, tenantB)
	tuplesB, err := s.ReadTuples(ctx, tenantB, store.TupleFilter{ObjectID: "secret_doc"}, revB+10)
	if err != nil {
		t.Fatalf("tenant B read failed: %v", err)
	}
	if len(tuplesB) != 0 {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Tenant B saw Tenant A tuples! Got: %v", tuplesB)
	}

	_ = revA
}

func TestStore_ConcurrentWritesStrictlyMonotonicAndNoLostTuples(t *testing.T) {
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_conc_" + strings.ReplaceAll(uid.String(), "-", "")
	setupTenantWithSchema(t, s, tenantID)

	const numWriters = 100
	var wg sync.WaitGroup
	revisions := make([]int64, numWriters)
	errs := make([]error, numWriters)

	for i := 0; i < numWriters; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			docID := fmt.Sprintf("doc_%03d", idx)
			t := store.Tuple{
				ObjectType:  "doc",
				ObjectID:    docID,
				Relation:    "owner",
				SubjectType: "user",
				SubjectID:   fmt.Sprintf("user_%03d", idx),
			}
			rev, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
				{Op: store.OpCreate, Tuple: t},
			})
			revisions[idx] = rev
			errs[idx] = err
		}(i)
	}

	wg.Wait()

	// Verify all writes succeeded
	revSet := make(map[int64]bool)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("writer %d failed: %v", i, err)
		}
		rev := revisions[i]
		if revSet[rev] {
			t.Fatalf("duplicate revision %d returned across concurrent writers", rev)
		}
		revSet[rev] = true
	}

	if len(revSet) != numWriters {
		t.Fatalf("expected %d distinct revisions, got %d", numWriters, len(revSet))
	}

	// Final revision must equal initial revision (1 from schema) + 100 = 101
	finalRev, err := s.GetTenantRevision(ctx, tenantID)
	if err != nil {
		t.Fatalf("failed to get final revision: %v", err)
	}
	if finalRev != 101 {
		t.Fatalf("expected final revision 101, got %d", finalRev)
	}

	// Verify all 100 tuples are readable at finalRev (no lost writes)
	allTuples, err := s.ReadTuples(ctx, tenantID, store.TupleFilter{ObjectType: "doc"}, finalRev)
	if err != nil {
		t.Fatalf("failed to read all tuples: %v", err)
	}
	if len(allTuples) != numWriters {
		t.Fatalf("expected %d tuples, got %d (lost writes detected!)", numWriters, len(allTuples))
	}
}
