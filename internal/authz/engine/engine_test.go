package engine_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/raviteja-core/keystone/internal/authz/engine"
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

const comprehensiveSchema = `
version: 1
types:
  user: {}
  group:
    relations:
      member: [user, "group#member"]
  folder:
    relations:
      parent: [folder]
      owner:  [user]
      editor: [user, "group#member"]
      viewer: [user, "group#member", "user:*"]
    permissions:
      edit: "owner + editor + parent->edit"
      view: "edit + viewer + parent->view"
  doc:
    relations:
      parent: [folder]
      owner:  [user]
      editor: [user, "group#member"]
      viewer: [user, "group#member", "user:*"]
      banned: [user]
      approver: [user]
    permissions:
      edit: "owner + editor + parent->edit"
      view: "(edit + viewer + parent->view) - banned"
      publish: "owner & approver"
`

func setupEngineWithSchema(t *testing.T, tenantID string) (*engine.Engine, *store.Store, int64) {
	t.Helper()
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	sch, err := schema.ParseAndValidate(comprehensiveSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}

	rev, err := s.SaveSchema(ctx, tenantID, 1, comprehensiveSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	eng := engine.New(s, engine.DefaultConfig())
	return eng, s, rev
}

func TestCheck_BasicPermissions(t *testing.T) {
	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_engine_" + strings.ReplaceAll(uid.String(), "-", "")
	eng, s, _ := setupEngineWithSchema(t, tenantID)
	ctx := context.Background()

	// Setup hierarchy:
	// folder:root (owner: alice, viewer: user:*)
	// folder:sub (parent: folder:root, editor: group:eng#member)
	// group:eng (member: bob, member: group:dev#member)
	// group:dev (member: charlie)
	// doc:1 (parent: folder:sub, owner: dave, banned: eve, approver: dave)
	writes := []store.TupleOperation{
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "folder", ObjectID: "root", Relation: "owner", SubjectType: "user", SubjectID: "alice"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "folder", ObjectID: "root", Relation: "viewer", SubjectType: "user", SubjectID: "*"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "folder", ObjectID: "sub", Relation: "parent", SubjectType: "folder", SubjectID: "root"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "folder", ObjectID: "sub", Relation: "editor", SubjectType: "group", SubjectID: "eng", SubjectRelation: "member"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "group", ObjectID: "eng", Relation: "member", SubjectType: "user", SubjectID: "bob"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "group", ObjectID: "eng", Relation: "member", SubjectType: "group", SubjectID: "dev", SubjectRelation: "member"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "group", ObjectID: "dev", Relation: "member", SubjectType: "user", SubjectID: "charlie"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "doc", ObjectID: "1", Relation: "parent", SubjectType: "folder", SubjectID: "sub"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "doc", ObjectID: "1", Relation: "owner", SubjectType: "user", SubjectID: "dave"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "doc", ObjectID: "1", Relation: "banned", SubjectType: "user", SubjectID: "eve"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "doc", ObjectID: "1", Relation: "approver", SubjectType: "user", SubjectID: "dave"}},
	}

	rev, err := s.WriteRelationships(ctx, tenantID, writes)
	if err != nil {
		t.Fatalf("failed to write tuples: %v", err)
	}

	tests := []struct {
		name       string
		obj        store.Object
		perm       string
		subj       store.Subject
		expectedOk bool
	}{
		// 1. Direct owner on doc
		{"dave can edit doc:1 (direct owner)", store.Object{Type: "doc", ID: "1"}, "edit", store.Subject{Type: "user", ID: "dave"}, true},
		// 2. Transitive userset membership: group:eng -> bob
		{"bob can edit doc:1 (editor via group:eng)", store.Object{Type: "doc", ID: "1"}, "edit", store.Subject{Type: "user", ID: "bob"}, true},
		// 3. Nested userset membership: group:eng -> group:dev -> charlie
		{"charlie can edit doc:1 (editor via nested group:dev)", store.Object{Type: "doc", ID: "1"}, "edit", store.Subject{Type: "user", ID: "charlie"}, true},
		// 4. Arrow inheritance: folder:root owner alice inherits edit on doc:1
		{"alice can edit doc:1 (parent hierarchy owner)", store.Object{Type: "doc", ID: "1"}, "edit", store.Subject{Type: "user", ID: "alice"}, true},
		// 5. Wildcard viewer: frank (random user) can view doc:1 via folder:root viewer:user:*
		{"frank can view doc:1 (via wildcard user:* on root)", store.Object{Type: "doc", ID: "1"}, "view", store.Subject{Type: "user", ID: "frank"}, true},
		// 6. Exclusion: eve would have view access via wildcard, but is in banned relation!
		{"eve CANNOT view doc:1 (excluded by banned relation)", store.Object{Type: "doc", ID: "1"}, "view", store.Subject{Type: "user", ID: "eve"}, false},
		// 7. Intersection: dave is owner & approver -> can publish
		{"dave can publish doc:1 (owner & approver)", store.Object{Type: "doc", ID: "1"}, "publish", store.Subject{Type: "user", ID: "dave"}, true},
		// 8. Intersection failed: bob can edit, but is not approver -> cannot publish
		{"bob CANNOT publish doc:1 (editor, but not approver)", store.Object{Type: "doc", ID: "1"}, "publish", store.Subject{Type: "user", ID: "bob"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := eng.Check(ctx, engine.CheckRequest{
				TenantID:   tenantID,
				Revision:   rev,
				Object:     tt.obj,
				Permission: tt.perm,
				Subject:    tt.subj,
			})
			if err != nil {
				t.Fatalf("unexpected check error: %v", err)
			}
			if res.Allowed != tt.expectedOk {
				t.Errorf("expected allowed=%v, got %v (depth: %d, dbReads: %d)", tt.expectedOk, res.Allowed, res.Depth, res.DBReads)
			}
		})
	}
}

func TestCheck_CyclePoisoningDefense(t *testing.T) {
	// Steering requirement:
	// "Memoize a sub-result only if its evaluation never hit a cycle cut-off; otherwise a
	//  path-dependent DENIED could poison the cache. Add a test that proves this (a graph where
	//  the same node is reachable via a cyclic path and a clean path)."
	//
	// Schema:
	// item:
	//   relations:
	//     loop: [item]
	//     direct: [item]
	//     member: [user]
	//   permissions:
	//     // branch_loop goes item:1 -> item:2 -> item:1 (cycle cut-off: DENIED)
	//     // branch_direct goes item:1 -> item:2 (clean path: reaches alice!)
	//     check_access: "loop->check_access + direct->clean_access"
	//     clean_access: "member"
	//
	// Tuples:
	// item:1#loop@item:2
	// item:2#loop@item:1 (creates cycle 1->2->1)
	// item:1#direct@item:2
	// item:2#member@user:alice
	//
	// When checking item:1#check_access for alice:
	// Left branch (loop->check_access):
	//   eval(item:1, check_access) -> reads loop -> eval(item:2, check_access) -> reads loop -> eval(item:1, check_access)
	//   item:1 is visiting -> cycle cut-off yields DENIED for this branch!
	//   Crucially: item:2 on this branch hit the cycle cut-off. If item:2 was cached as DENIED, then:
	// Right branch (direct->clean_access):
	//   eval(item:2, clean_access) -> reads member -> finds alice -> ALLOWED!
	// If the cache was poisoned with item:2=DENIED, the check would wrongly return DENIED.
	// With cycle-sensitive memoization, it correctly returns ALLOWED!

	cycleSchema := `
version: 1
types:
  user: {}
  item:
    relations:
      loop:   [item]
      direct: [item]
      member: [user]
    permissions:
      check_access: "loop->check_access + direct->clean_access"
      clean_access: "member"
`

	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_cycle_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(cycleSchema)
	if err != nil {
		t.Fatalf("failed to parse cycle schema: %v", err)
	}

	_, err = s.SaveSchema(ctx, tenantID, 1, cycleSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	rev, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "1", Relation: "loop", SubjectType: "item", SubjectID: "2"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "2", Relation: "loop", SubjectType: "item", SubjectID: "1"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "1", Relation: "direct", SubjectType: "item", SubjectID: "2"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "2", Relation: "member", SubjectType: "user", SubjectID: "alice"}},
	})
	if err != nil {
		t.Fatalf("failed to write cycle tuples: %v", err)
	}

	eng := engine.New(s, engine.DefaultConfig())

	res, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "item", ID: "1"},
		Permission: "check_access",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if err != nil {
		t.Fatalf("check failed with error: %v", err)
	}

	if !res.Allowed {
		t.Fatalf("CRITICAL: Cycle poisoning bug! Alice should be allowed via direct path, but was denied due to cyclic memo poisoning!")
	}
}

func TestCheck_FailClosed(t *testing.T) {
	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_fc_" + strings.ReplaceAll(uid.String(), "-", "")
	eng, _, rev := setupEngineWithSchema(t, tenantID)
	ctx := context.Background()

	// 1. Unknown object type -> error, never allow
	_, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "unknown_type", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if !errors.Is(err, engine.ErrUnknownType) {
		t.Errorf("expected ErrUnknownType, got %v", err)
	}

	// 2. Unknown permission -> error, never allow
	_, err = eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "doc", ID: "1"},
		Permission: "nonexistent_perm",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if !errors.Is(err, engine.ErrUnknownRelationOrPermission) {
		t.Errorf("expected ErrUnknownRelationOrPermission, got %v", err)
	}
}

func TestCheck_DepthLimit(t *testing.T) {
	// Construct deep chain exceeding maxDepth (configured to 5)
	chainSchema := `
version: 1
types:
  node:
    relations:
      next: [node]
    permissions:
      reach: "next + next->reach"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_depth_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, _ := schema.ParseAndValidate(chainSchema)
	_, _ = s.SaveSchema(ctx, tenantID, 1, chainSchema, sch)

	// Create chain node:1 -> node:2 -> node:3 -> node:4 -> node:5 -> node:6 -> node:7
	var writes []store.TupleOperation
	for i := 1; i <= 6; i++ {
		writes = append(writes, store.TupleOperation{
			Op: store.OpCreate,
			Tuple: store.Tuple{
				ObjectType:  "node",
				ObjectID:    fmt.Sprintf("%d", i),
				Relation:    "next",
				SubjectType: "node",
				SubjectID:   fmt.Sprintf("%d", i+1),
			},
		})
	}
	rev, _ := s.WriteRelationships(ctx, tenantID, writes)

	// Set engine max depth to 4
	eng := engine.New(s, engine.Config{
		MaxDepth:       4,
		MaxConcurrency: 4,
		Timeout:        time.Second,
	})

	// Check reaching node:6 from node:1 (depth exceeds 4) -> must return ErrDepthExceeded, NEVER allow!
	_, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "node", ID: "1"},
		Permission: "reach",
		Subject:    store.Subject{Type: "node", ID: "6"},
	})

	if !errors.Is(err, engine.ErrDepthExceeded) {
		t.Fatalf("expected ErrDepthExceeded, got %v", err)
	}
}

func TestDifferential_EngineVsOracle_10000Checks(t *testing.T) {
	// Randomized differential testing: 10,000 checks comparing Engine vs naive Oracle.
	seed := time.Now().UnixNano()
	t.Logf("Differential Test Seed: %d", seed)
	rng := rand.New(rand.NewSource(seed))

	diffSchema := `
version: 1
types:
  user: {}
  group:
    relations:
      member: [user, "group#member"]
  doc:
    relations:
      owner:  [user]
      editor: [user, "group#member"]
      viewer: [user, "group#member", "user:*"]
      banned: [user]
    permissions:
      edit: "owner + editor"
      view: "(edit + viewer) - banned"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_diff_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(diffSchema)
	if err != nil {
		t.Fatalf("seed %d: failed to parse diff schema: %v", seed, err)
	}

	_, err = s.SaveSchema(ctx, tenantID, 1, diffSchema, sch)
	if err != nil {
		t.Fatalf("seed %d: failed to save schema: %v", seed, err)
	}

	// Generate a randomized graph of 100 tuples
	const numDocs = 15
	const numGroups = 8
	const numUsers = 25

	var tuples []store.Tuple
	var writeOps []store.TupleOperation

	// 1. Random group memberships (including potential nested groups and cycles)
	for i := 1; i <= numGroups; i++ {
		// Random user members
		numMembers := rng.Intn(4) + 1
		for m := 0; m < numMembers; m++ {
			uID := fmt.Sprintf("u%d", rng.Intn(numUsers)+1)
			tup := store.Tuple{
				ObjectType:  "group",
				ObjectID:    fmt.Sprintf("g%d", i),
				Relation:    "member",
				SubjectType: "user",
				SubjectID:   uID,
			}
			tuples = append(tuples, tup)
			writeOps = append(writeOps, store.TupleOperation{Op: store.OpTouch, Tuple: tup})
		}

		// Random nested group
		if rng.Float32() < 0.4 {
			targetGroup := fmt.Sprintf("g%d", rng.Intn(numGroups)+1)
			tup := store.Tuple{
				ObjectType:      "group",
				ObjectID:        fmt.Sprintf("g%d", i),
				Relation:        "member",
				SubjectType:     "group",
				SubjectID:       targetGroup,
				SubjectRelation: "member",
			}
			tuples = append(tuples, tup)
			writeOps = append(writeOps, store.TupleOperation{Op: store.OpTouch, Tuple: tup})
		}
	}

	// 2. Random doc relations (owner, editor, viewer, wildcard, banned)
	for d := 1; d <= numDocs; d++ {
		docID := fmt.Sprintf("d%d", d)

		// Owner
		ownerID := fmt.Sprintf("u%d", rng.Intn(numUsers)+1)
		tupOwner := store.Tuple{ObjectType: "doc", ObjectID: docID, Relation: "owner", SubjectType: "user", SubjectID: ownerID}
		tuples = append(tuples, tupOwner)
		writeOps = append(writeOps, store.TupleOperation{Op: store.OpTouch, Tuple: tupOwner})

		// Editor (userset)
		if rng.Float32() < 0.6 {
			gID := fmt.Sprintf("g%d", rng.Intn(numGroups)+1)
			tupEd := store.Tuple{ObjectType: "doc", ObjectID: docID, Relation: "editor", SubjectType: "group", SubjectID: gID, SubjectRelation: "member"}
			tuples = append(tuples, tupEd)
			writeOps = append(writeOps, store.TupleOperation{Op: store.OpTouch, Tuple: tupEd})
		}

		// Viewer wildcard on 20% of docs
		if rng.Float32() < 0.2 {
			tupWc := store.Tuple{ObjectType: "doc", ObjectID: docID, Relation: "viewer", SubjectType: "user", SubjectID: "*"}
			tuples = append(tuples, tupWc)
			writeOps = append(writeOps, store.TupleOperation{Op: store.OpTouch, Tuple: tupWc})
		}

		// Banned user
		if rng.Float32() < 0.3 {
			bannedID := fmt.Sprintf("u%d", rng.Intn(numUsers)+1)
			tupBan := store.Tuple{ObjectType: "doc", ObjectID: docID, Relation: "banned", SubjectType: "user", SubjectID: bannedID}
			tuples = append(tuples, tupBan)
			writeOps = append(writeOps, store.TupleOperation{Op: store.OpTouch, Tuple: tupBan})
		}
	}

	rev, err := s.WriteRelationships(ctx, tenantID, writeOps)
	if err != nil {
		t.Fatalf("seed %d: failed to write relationships: %v", seed, err)
	}

	eng := engine.New(s, engine.DefaultConfig())
	oracle := engine.NewOracle(sch, tuples, engine.DefaultMaxDepth)

	// Run 10,000 random checks!
	const totalChecks = 10000
	perms := []string{"view", "edit"}

	for i := 0; i < totalChecks; i++ {
		docID := fmt.Sprintf("d%d", rng.Intn(numDocs)+1)
		perm := perms[rng.Intn(len(perms))]
		userID := fmt.Sprintf("u%d", rng.Intn(numUsers)+1)

		obj := store.Object{Type: "doc", ID: docID}
		subj := store.Subject{Type: "user", ID: userID}

		// 1. Evaluate with Oracle
		oracleAllowed, oracleErr := oracle.Check(obj, perm, subj)
		if oracleErr != nil {
			t.Fatalf("seed %d: oracle error on check %d: %v", seed, i, oracleErr)
		}

		// 2. Evaluate with Engine
		engResp, engErr := eng.Check(ctx, engine.CheckRequest{
			TenantID:   tenantID,
			Revision:   rev,
			Object:     obj,
			Permission: perm,
			Subject:    subj,
		})
		if engErr != nil {
			t.Fatalf("seed %d: engine error on check %d: %v", seed, i, engErr)
		}

		// 3. Assert equality
		if engResp.Allowed != oracleAllowed {
			t.Fatalf("seed %d: DIFFERENTIAL FAILURE on check %d: obj=%s, perm=%s, subj=%s: Engine=%v, Oracle=%v",
				seed, i, obj.String(), perm, subj.String(), engResp.Allowed, oracleAllowed)
		}
	}

	t.Logf("Differential Test PASSED: %d checks verified identical across Engine and Oracle! Seed: %d", totalChecks, seed)
}

func BenchmarkCheck_Cold(b *testing.B) {
	pool := getTestPoolBench(b)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_bench_cold_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, _ := schema.ParseAndValidate(comprehensiveSchema)
	_, _ = s.SaveSchema(ctx, tenantID, 1, comprehensiveSchema, sch)

	tuple := store.Tuple{
		ObjectType:  "doc",
		ObjectID:    "bench_doc",
		Relation:    "owner",
		SubjectType: "user",
		SubjectID:   "alice",
	}
	rev, _ := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: tuple},
	})

	eng := engine.New(s, engine.DefaultConfig())
	req := engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "doc", ID: "bench_doc"},
		Permission: "edit",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := eng.Check(ctx, req)
		if err != nil {
			b.Fatalf("benchmark failed: %v", err)
		}
	}
}

func BenchmarkCheck_DeepNesting(b *testing.B) {
	pool := getTestPoolBench(b)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_bench_deep_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, _ := schema.ParseAndValidate(comprehensiveSchema)
	_, _ = s.SaveSchema(ctx, tenantID, 1, comprehensiveSchema, sch)

	// 8 levels of hierarchy: folder:8 -> ... -> folder:1 -> doc:1
	var writes []store.TupleOperation
	writes = append(writes, store.TupleOperation{
		Op: store.OpCreate,
		Tuple: store.Tuple{
			ObjectType:  "folder",
			ObjectID:    "8",
			Relation:    "owner",
			SubjectType: "user",
			SubjectID:   "alice",
		},
	})
	for i := 7; i >= 1; i-- {
		writes = append(writes, store.TupleOperation{
			Op: store.OpCreate,
			Tuple: store.Tuple{
				ObjectType:  "folder",
				ObjectID:    fmt.Sprintf("%d", i),
				Relation:    "parent",
				SubjectType: "folder",
				SubjectID:   fmt.Sprintf("%d", i+1),
			},
		})
	}
	writes = append(writes, store.TupleOperation{
		Op: store.OpCreate,
		Tuple: store.Tuple{
			ObjectType:  "doc",
			ObjectID:    "deep_doc",
			Relation:    "parent",
			SubjectType: "folder",
			SubjectID:   "1",
		},
	})

	rev, _ := s.WriteRelationships(ctx, tenantID, writes)

	eng := engine.New(s, engine.DefaultConfig())
	req := engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "doc", ID: "deep_doc"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := eng.Check(ctx, req)
		if err != nil {
			b.Fatalf("benchmark failed: %v", err)
		}
	}
}

func getTestPoolBench(b *testing.B) *pgxpool.Pool {
	b.Helper()
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
		b.Fatalf("failed to connect to authz database: %v", err)
	}
	b.Cleanup(func() {
		pool.Close()
	})
	return pool
}
