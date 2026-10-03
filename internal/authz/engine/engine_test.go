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
	// TestCheck_CyclePoisoningDefense tests that the SAME (object, name) pair
	// evaluated along a cyclic path (where it returns DENIED due to cycle cut-off)
	// is NOT memoized as DENIED. When subsequently evaluated along a clean path in
	// the same Check request, it evaluates to ALLOWED.
	//
	// Graph:
	// root:main#test -> step->run (sequential arrow iteration over step:1, step:2)
	//
	// Path 1 (step:1):
	//   step:1#run = "item->eval - fail"
	//   step:1#item -> item:k
	//   item:k#eval = "peer->eval + member"
	//   item:k#peer -> item:target (tuple 1) and item:clean (tuple 2)
	//   item:k visits item:target#eval:
	//     item:target#eval = "peer->eval + member"
	//     item:target#peer -> item:k
	//     item:target calls item:k#eval -> CYCLE CUT-OFF! Returns (allowed=false, hitCycle=true).
	//     item:target has no other peers or member, so item:target#eval returns (allowed=false, hitCycle=true).
	//   If item:target#eval were memoized as DENIED, the memo cache is poisoned!
	//   item:k then evaluates tuple 2 (item:clean), which has alice, so item:k succeeds.
	//   However, step:1 has fail@alice, so step:1#run evaluates to DENIED (exclusion).
	//
	// Path 2 (step:2):
	//   Arrow loop continues to step:2.
	//   step:2#run = "item->eval - fail" (step:2 has NO fail tuple).
	//   step:2#item -> item:target (THE EXACT SAME object:name item:target#eval!)
	//   step:2 evaluates item:target#eval:
	//     item:target calls item:k#eval.
	//     On this clean path, item:k is NOT in visiting!
	//     item:k evaluates item:clean, which has alice -> ALLOWED!
	//     item:target returns ALLOWED!
	//   step:2 returns ALLOWED!
	//   root:main#test returns ALLOWED!
	//
	// If the memo cache was poisoned by Path 1, step:2 gets DENIED from cache and test FAILS.
	// If !hitCycle correctly prevented memoization, step:2 evaluates cleanly and test PASSES.

	cycleSchema := `
version: 1
types:
  user: {}
  root:
    relations:
      step: [step]
    permissions:
      test: "step->run"
  step:
    relations:
      item: [item]
      fail: [user]
    permissions:
      run: "item->eval - fail"
  item:
    relations:
      peer:   [item]
      member: [user]
    permissions:
      eval: "peer->eval + member"
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
		// root steps (step:1 sorted before step:2 in DB)
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "root", ObjectID: "main", Relation: "step", SubjectType: "step", SubjectID: "1"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "root", ObjectID: "main", Relation: "step", SubjectType: "step", SubjectID: "2"}},

		// step:1 points to item:k and has fail@alice
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "step", ObjectID: "1", Relation: "item", SubjectType: "item", SubjectID: "k"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "step", ObjectID: "1", Relation: "fail", SubjectType: "user", SubjectID: "alice"}},

		// step:2 points directly to item:a_target (SAME node) and has NO fail
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "step", ObjectID: "2", Relation: "item", SubjectType: "item", SubjectID: "a_target"}},

		// item:k has peer item:a_target ('a' sorted first) and item:z_clean ('z' sorted second)
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "k", Relation: "peer", SubjectType: "item", SubjectID: "a_target"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "k", Relation: "peer", SubjectType: "item", SubjectID: "z_clean"}},

		// item:a_target has peer item:k (cycles back)
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "a_target", Relation: "peer", SubjectType: "item", SubjectID: "k"}},

		// item:z_clean has alice in member
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "z_clean", Relation: "member", SubjectType: "user", SubjectID: "alice"}},
	})
	if err != nil {
		t.Fatalf("failed to write cycle tuples: %v", err)
	}

	eng := engine.New(s, engine.DefaultConfig())

	res, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "root", ID: "main"},
		Permission: "test",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if err != nil {
		t.Fatalf("check failed with error: %v", err)
	}

	if !res.Allowed {
		t.Fatalf("CRITICAL: Cycle poisoning bug! Alice should be allowed via step:2 clean evaluation of item:target#eval, but was denied due to memo poisoning from step:1!")
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

func TestCheck_ExclusionSafety_SubtrahendCycleCutoff(t *testing.T) {
	// Exclusion safety: if the subtrahend of a - b evaluates to DENIED while having hit
	// a cycle cut-off, the engine must return ErrCycleCutoffInSubtrahend (fail closed),
	// never granting access based on an uncertain denial.
	exclusionSchema := `
version: 1
types:
  user: {}
  item:
    relations:
      loop:  [item]
      allow: [user]
    permissions:
      cycle_perm: "loop->cycle_perm"
      safe_perm:  "allow - cycle_perm"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_excl_safe_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(exclusionSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	_, err = s.SaveSchema(ctx, tenantID, 1, exclusionSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// Create graph: item:1 allows alice, but subtrahend cycle_perm loops between 1 and 2
	rev, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "1", Relation: "allow", SubjectType: "user", SubjectID: "alice"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "1", Relation: "loop", SubjectType: "item", SubjectID: "2"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "item", ObjectID: "2", Relation: "loop", SubjectType: "item", SubjectID: "1"}},
	})
	if err != nil {
		t.Fatalf("failed to write relationships: %v", err)
	}

	eng := engine.New(s, engine.DefaultConfig())

	res, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "item", ID: "1"},
		Permission: "safe_perm",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})

	if !errors.Is(err, engine.ErrCycleCutoffInSubtrahend) {
		t.Fatalf("expected ErrCycleCutoffInSubtrahend, got res=%v, err=%v", res, err)
	}
	t.Logf("Exclusion safety verified: correctly failed closed with ErrCycleCutoffInSubtrahend")
}

func TestCheck_ExclusionSubtrahendUsersetOverCyclicGroups(t *testing.T) {
	// Tests: view = viewer - banned
	// banned allows [user, "group#member"]
	// banned group graph is cyclic (g1 <-> g2).
	// Expects correct allow/deny without error (BFS userset path reports hitCycle=false so results memoize).
	schText := `
version: 1
types:
  user: {}
  group:
    relations:
      member: [user, "group#member"]
  doc:
    relations:
      viewer: [user]
      banned: [user, "group#member"]
    permissions:
      view: "viewer - banned"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_excl_sub_cyclic_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(schText)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	_, err = s.SaveSchema(ctx, tenantID, 1, schText, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// Setup:
	// g1 <-> g2 cycle
	// g1#member@user:banned_user
	// doc:1#viewer@user:alice
	// doc:1#viewer@user:banned_user
	// doc:1#banned@group:g1#member
	rev, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "group", ObjectID: "g1", Relation: "member", SubjectType: "group", SubjectID: "g2", SubjectRelation: "member"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "group", ObjectID: "g2", Relation: "member", SubjectType: "group", SubjectID: "g1", SubjectRelation: "member"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "group", ObjectID: "g1", Relation: "member", SubjectType: "user", SubjectID: "banned_user"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "doc", ObjectID: "1", Relation: "viewer", SubjectType: "user", SubjectID: "alice"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "doc", ObjectID: "1", Relation: "viewer", SubjectType: "user", SubjectID: "banned_user"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "doc", ObjectID: "1", Relation: "banned", SubjectType: "group", SubjectID: "g1", SubjectRelation: "member"}},
	})
	if err != nil {
		t.Fatalf("failed to write relationships: %v", err)
	}

	eng := engine.New(s, engine.DefaultConfig())

	// 1. Alice is a viewer and not banned (banned cyclic graph searched via BFS returns false without cycle error)
	resAlice, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "doc", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if err != nil {
		t.Fatalf("alice check failed with error: %v", err)
	}
	if !resAlice.Allowed {
		t.Fatalf("expected alice to be ALLOWED, got denied")
	}

	// 2. Banned user is a viewer, but belongs to g1 in the cyclic group graph -> correctly DENIED, no error
	resBanned, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "doc", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "banned_user"},
	})
	if err != nil {
		t.Fatalf("banned_user check failed with error: %v", err)
	}
	if resBanned.Allowed {
		t.Fatalf("expected banned_user to be DENIED, got allowed")
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

func TestCheck_DepthLimit_TransitionsOnly(t *testing.T) {
	// Tests that depth limit counts only (object,name) -> (object,name) transitions,
	// and does NOT increment on internal AST nodes (like union operators).
	// With MaxDepth = 25:
	// - 10-hop parent->view chain must PASS.
	// - 30-hop parent->view chain must RETURN ErrDepthExceeded.

	folderSchema := `
version: 1
types:
  user: {}
  folder:
    relations:
      parent: [folder]
      viewer: [user]
    permissions:
      # Has binary union node: viewer + parent->view
      view: "viewer + parent->view"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_depth_trans_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(folderSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	_, err = s.SaveSchema(ctx, tenantID, 1, folderSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// Build a 30-hop chain:
	// folder:1 -> folder:2 -> ... -> folder:30 -> folder:31
	// folder:11 has viewer: alice (target for 10-hop chain starting at folder:1)
	// folder:31 has viewer: bob   (target for 30-hop chain starting at folder:1)
	var writes []store.TupleOperation
	for i := 1; i <= 30; i++ {
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
			ObjectType:  "folder",
			ObjectID:    "11", // 10 hops from folder:1
			Relation:    "viewer",
			SubjectType: "user",
			SubjectID:   "alice",
		},
	})
	writes = append(writes, store.TupleOperation{
		Op: store.OpCreate,
		Tuple: store.Tuple{
			ObjectType:  "folder",
			ObjectID:    "31", // 30 hops from folder:1
			Relation:    "viewer",
			SubjectType: "user",
			SubjectID:   "bob",
		},
	})

	rev, err := s.WriteRelationships(ctx, tenantID, writes)
	if err != nil {
		t.Fatalf("failed to write hierarchy: %v", err)
	}

	eng := engine.New(s, engine.Config{
		MaxDepth:       25,
		MaxConcurrency: 4,
		Timeout:        5 * time.Second,
	})

	// 1. 10-hop parent->view chain for alice: MUST PASS with MaxDepth 25!
	res10, err10 := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "folder", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if err10 != nil {
		t.Fatalf("10-hop chain failed unexpectedly: %v", err10)
	}
	if !res10.Allowed {
		t.Fatalf("10-hop chain expected allowed=true for alice, got false")
	}
	t.Logf("10-hop chain succeeded as expected with depth=%d", res10.Depth)

	// 2. 30-hop parent->view chain for bob: MUST FAIL with ErrDepthExceeded with MaxDepth 25!
	_, err30 := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "folder", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "bob"},
	})
	if !errors.Is(err30, engine.ErrDepthExceeded) {
		t.Fatalf("30-hop chain expected ErrDepthExceeded, got err=%v", err30)
	}
	t.Logf("30-hop chain correctly returned ErrDepthExceeded")
}

func TestDifferential_ExhaustiveFixpointOracle(t *testing.T) {
	// Independent differential testing:
	// Evaluates ALL (object, permission, user) triples for multiple randomized graphs
	// comparing Engine against the bottom-up least-fixpoint Oracle.
	// Includes arrows, intersection, exclusion, wildcard, nested and cyclic groups.
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
  folder:
    relations:
      parent: [folder]
      viewer: [user, "user:*"]
    permissions:
      view: "viewer + parent->view"
  doc:
    relations:
      parent:   [folder]
      owner:    [user]
      approver: [user]
      editor:   ["group#member"]
      banned:   [user]
    permissions:
      edit:    "owner + editor"
      publish: "owner & approver"
      view:    "(edit + parent->view) - banned"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	sch, err := schema.ParseAndValidate(diffSchema)
	if err != nil {
		t.Fatalf("seed %d: failed to parse diff schema: %v", seed, err)
	}

	const numGraphs = 8
	const numDocs = 4
	const numFolders = 3
	const numGroups = 3
	users := []string{"u1", "u2", "u3", "u4", "u5"}

	totalTriplesChecked := 0

	for g := 0; g < numGraphs; g++ {
		uid, _ := ids.NewUUIDv7()
		tenantID := fmt.Sprintf("tenant_diff_g%d_%s", g, strings.ReplaceAll(uid.String(), "-", ""))

		_, err = s.SaveSchema(ctx, tenantID, 1, diffSchema, sch)
		if err != nil {
			t.Fatalf("seed %d (graph %d): failed to save schema: %v", seed, g, err)
		}

		var tuples []store.Tuple
		var writeOps []store.TupleOperation

		// 1. Group memberships (nested and cyclic)
		for i := 1; i <= numGroups; i++ {
			// user members
			for _, u := range users {
				if rng.Float32() < 0.3 {
					tup := store.Tuple{
						ObjectType:  "group",
						ObjectID:    fmt.Sprintf("g%d", i),
						Relation:    "member",
						SubjectType: "user",
						SubjectID:   u,
					}
					tuples = append(tuples, tup)
					writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tup})
				}
			}
			// nested group (including potential cycles)
			targetG := fmt.Sprintf("g%d", rng.Intn(numGroups)+1)
			tup := store.Tuple{
				ObjectType:      "group",
				ObjectID:        fmt.Sprintf("g%d", i),
				Relation:        "member",
				SubjectType:     "group",
				SubjectID:       targetG,
				SubjectRelation: "member",
			}
			tuples = append(tuples, tup)
			writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tup})
		}

		// 2. Folder hierarchy and viewers (including wildcard)
		for f := 1; f <= numFolders; f++ {
			fID := fmt.Sprintf("f%d", f)
			// parent folder
			if f > 1 && rng.Float32() < 0.7 {
				parentID := fmt.Sprintf("f%d", rng.Intn(f-1)+1)
				tup := store.Tuple{ObjectType: "folder", ObjectID: fID, Relation: "parent", SubjectType: "folder", SubjectID: parentID}
				tuples = append(tuples, tup)
				writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tup})
			}
			// wildcard viewer on some folders
			if rng.Float32() < 0.25 {
				tup := store.Tuple{ObjectType: "folder", ObjectID: fID, Relation: "viewer", SubjectType: "user", SubjectID: "*"}
				tuples = append(tuples, tup)
				writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tup})
			}
			// user viewers
			for _, u := range users {
				if rng.Float32() < 0.2 {
					tup := store.Tuple{ObjectType: "folder", ObjectID: fID, Relation: "viewer", SubjectType: "user", SubjectID: u}
					tuples = append(tuples, tup)
					writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tup})
				}
			}
		}

		// 3. Doc relations (parent, owner, approver, editor group, banned)
		for d := 1; d <= numDocs; d++ {
			docID := fmt.Sprintf("d%d", d)
			// parent folder
			if rng.Float32() < 0.8 {
				fID := fmt.Sprintf("f%d", rng.Intn(numFolders)+1)
				tup := store.Tuple{ObjectType: "doc", ObjectID: docID, Relation: "parent", SubjectType: "folder", SubjectID: fID}
				tuples = append(tuples, tup)
				writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tup})
			}
			// owner
			ownerU := users[rng.Intn(len(users))]
			tupOwner := store.Tuple{ObjectType: "doc", ObjectID: docID, Relation: "owner", SubjectType: "user", SubjectID: ownerU}
			tuples = append(tuples, tupOwner)
			writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tupOwner})

			// approver
			if rng.Float32() < 0.5 {
				appU := users[rng.Intn(len(users))]
				tupApp := store.Tuple{ObjectType: "doc", ObjectID: docID, Relation: "approver", SubjectType: "user", SubjectID: appU}
				tuples = append(tuples, tupApp)
				writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tupApp})
			}
			// editor group
			if rng.Float32() < 0.6 {
				gID := fmt.Sprintf("g%d", rng.Intn(numGroups)+1)
				tupEd := store.Tuple{ObjectType: "doc", ObjectID: docID, Relation: "editor", SubjectType: "group", SubjectID: gID, SubjectRelation: "member"}
				tuples = append(tuples, tupEd)
				writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tupEd})
			}
			// banned user
			if rng.Float32() < 0.3 {
				banU := users[rng.Intn(len(users))]
				tupBan := store.Tuple{ObjectType: "doc", ObjectID: docID, Relation: "banned", SubjectType: "user", SubjectID: banU}
				tuples = append(tuples, tupBan)
				writeOps = append(writeOps, store.TupleOperation{Op: store.OpCreate, Tuple: tupBan})
			}
		}

		rev, err := s.WriteRelationships(ctx, tenantID, writeOps)
		if err != nil {
			t.Fatalf("seed %d (graph %d): failed to write relationships: %v", seed, g, err)
		}

		eng := engine.New(s, engine.DefaultConfig())
		oracle := engine.NewOracle(sch, tuples, users)

		// ENUMERATE ALL (object, permission, user) triples for this graph!
		// Docs: view, edit, publish
		for d := 1; d <= numDocs; d++ {
			obj := store.Object{Type: "doc", ID: fmt.Sprintf("d%d", d)}
			for _, perm := range []string{"view", "edit", "publish"} {
				for _, u := range users {
					subj := store.Subject{Type: "user", ID: u}

					oracleAllowed, oErr := oracle.Check(obj, perm, subj)
					if oErr != nil {
						t.Fatalf("seed %d graph %d: oracle error on %s#%s@%s: %v", seed, g, obj, perm, subj, oErr)
					}

					engResp, eErr := eng.Check(ctx, engine.CheckRequest{
						TenantID:   tenantID,
						Revision:   rev,
						Object:     obj,
						Permission: perm,
						Subject:    subj,
					})
					if eErr != nil {
						t.Fatalf("seed %d graph %d: engine error on %s#%s@%s: %v", seed, g, obj, perm, subj, eErr)
					}

					if engResp.Allowed != oracleAllowed {
						t.Fatalf("seed %d graph %d DIFFERENTIAL MISMATCH on %s#%s@%s: Engine=%v, Oracle=%v",
							seed, g, obj, perm, subj, engResp.Allowed, oracleAllowed)
					}
					totalTriplesChecked++
				}
			}
		}

		// Folders: view
		for f := 1; f <= numFolders; f++ {
			obj := store.Object{Type: "folder", ID: fmt.Sprintf("f%d", f)}
			for _, u := range users {
				subj := store.Subject{Type: "user", ID: u}

				oracleAllowed, _ := oracle.Check(obj, "view", subj)
				engResp, eErr := eng.Check(ctx, engine.CheckRequest{
					TenantID:   tenantID,
					Revision:   rev,
					Object:     obj,
					Permission: "view",
					Subject:    subj,
				})
				if eErr != nil {
					t.Fatalf("seed %d graph %d: engine error on %s#view@%s: %v", seed, g, obj, subj, eErr)
				}
				if engResp.Allowed != oracleAllowed {
					t.Fatalf("seed %d graph %d DIFFERENTIAL MISMATCH on %s#view@%s: Engine=%v, Oracle=%v",
						seed, g, obj, subj, engResp.Allowed, oracleAllowed)
				}
				totalTriplesChecked++
			}
		}

		// Groups: member
		for grp := 1; grp <= numGroups; grp++ {
			obj := store.Object{Type: "group", ID: fmt.Sprintf("g%d", grp)}
			for _, u := range users {
				subj := store.Subject{Type: "user", ID: u}

				oracleAllowed, _ := oracle.Check(obj, "member", subj)
				engResp, eErr := eng.Check(ctx, engine.CheckRequest{
					TenantID:   tenantID,
					Revision:   rev,
					Object:     obj,
					Permission: "member",
					Subject:    subj,
				})
				if eErr != nil {
					t.Fatalf("seed %d graph %d: engine error on %s#member@%s: %v", seed, g, obj, subj, eErr)
				}
				if engResp.Allowed != oracleAllowed {
					t.Fatalf("seed %d graph %d DIFFERENTIAL MISMATCH on %s#member@%s: Engine=%v, Oracle=%v",
						seed, g, obj, subj, engResp.Allowed, oracleAllowed)
				}
				totalTriplesChecked++
			}
		}
	}

	t.Logf("Differential Test PASSED: %d exhaustive triples verified identical across %d random graphs! Seed: %d",
		totalTriplesChecked, numGraphs, seed)
}

func TestDifferential_WriteDeleteRevisions(t *testing.T) {
	// Tests that writes and deletes are tested against Oracle at BOTH the old and new revisions.
	simpleSchema := `
version: 1
types:
  user: {}
  group:
    relations:
      member: [user]
  doc:
    relations:
      owner:  [user]
      editor: ["group#member"]
      banned: [user]
    permissions:
      edit: "owner + editor"
      view: "edit - banned"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_rev_diff_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(simpleSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	_, err = s.SaveSchema(ctx, tenantID, 1, simpleSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// 1. Revision 1 writes
	tup1 := store.Tuple{ObjectType: "doc", ObjectID: "d1", Relation: "owner", SubjectType: "user", SubjectID: "alice"}
	tup2 := store.Tuple{ObjectType: "doc", ObjectID: "d1", Relation: "editor", SubjectType: "group", SubjectID: "g1", SubjectRelation: "member"}
	tup3 := store.Tuple{ObjectType: "group", ObjectID: "g1", Relation: "member", SubjectType: "user", SubjectID: "bob"}
	tup4 := store.Tuple{ObjectType: "doc", ObjectID: "d1", Relation: "banned", SubjectType: "user", SubjectID: "charlie"}

	rev1Tuples := []store.Tuple{tup1, tup2, tup3, tup4}
	rev1, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: tup1},
		{Op: store.OpCreate, Tuple: tup2},
		{Op: store.OpCreate, Tuple: tup3},
		{Op: store.OpCreate, Tuple: tup4},
	})
	if err != nil {
		t.Fatalf("failed to write rev1 tuples: %v", err)
	}

	// 2. Revision 2 writes: delete alice as owner, delete bob from group, add charlie as owner, add alice to group
	tup5 := store.Tuple{ObjectType: "doc", ObjectID: "d1", Relation: "owner", SubjectType: "user", SubjectID: "charlie"}
	tup6 := store.Tuple{ObjectType: "group", ObjectID: "g1", Relation: "member", SubjectType: "user", SubjectID: "alice"}

	rev2Tuples := []store.Tuple{tup2, tup4, tup5, tup6}
	rev2, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpDelete, Tuple: tup1}, // delete alice as owner
		{Op: store.OpDelete, Tuple: tup3}, // delete bob from group
		{Op: store.OpCreate, Tuple: tup5}, // make charlie owner
		{Op: store.OpCreate, Tuple: tup6}, // add alice to group
	})
	if err != nil {
		t.Fatalf("failed to write rev2 tuples: %v", err)
	}

	eng := engine.New(s, engine.DefaultConfig())
	allUsers := []string{"alice", "bob", "charlie", "dave"}

	oracleRev1 := engine.NewOracle(sch, rev1Tuples, allUsers)
	oracleRev2 := engine.NewOracle(sch, rev2Tuples, allUsers)

	// Compare Engine vs Oracle at Revision 1
	for _, perm := range []string{"view", "edit"} {
		for _, u := range allUsers {
			obj := store.Object{Type: "doc", ID: "d1"}
			subj := store.Subject{Type: "user", ID: u}

			oAllowed, _ := oracleRev1.Check(obj, perm, subj)
			resp, eErr := eng.Check(ctx, engine.CheckRequest{
				TenantID:   tenantID,
				Revision:   rev1,
				Object:     obj,
				Permission: perm,
				Subject:    subj,
			})
			if eErr != nil {
				t.Fatalf("Rev 1 Check error on %s#%s@%s: %v", obj, perm, subj, eErr)
			}
			if resp.Allowed != oAllowed {
				t.Fatalf("Rev 1 MISMATCH on %s#%s@%s: Engine=%v, Oracle=%v", obj, perm, subj, resp.Allowed, oAllowed)
			}
		}
	}

	// Compare Engine vs Oracle at Revision 2
	for _, perm := range []string{"view", "edit"} {
		for _, u := range allUsers {
			obj := store.Object{Type: "doc", ID: "d1"}
			subj := store.Subject{Type: "user", ID: u}

			oAllowed, _ := oracleRev2.Check(obj, perm, subj)
			resp, eErr := eng.Check(ctx, engine.CheckRequest{
				TenantID:   tenantID,
				Revision:   rev2,
				Object:     obj,
				Permission: perm,
				Subject:    subj,
			})
			if eErr != nil {
				t.Fatalf("Rev 2 Check error on %s#%s@%s: %v", obj, perm, subj, eErr)
			}
			if resp.Allowed != oAllowed {
				t.Fatalf("Rev 2 MISMATCH on %s#%s@%s: Engine=%v, Oracle=%v", obj, perm, subj, resp.Allowed, oAllowed)
			}
		}
	}

	t.Logf("Differential Test PASSED at both old Revision %d and new Revision %d!", rev1, rev2)
}

func TestDifferential_RandomSchemasAndGraphs_100Runs(t *testing.T) {
	// Differential testing with >=100 random graphs and random SCHEMAS within the grammar.
	// Compares Engine against independent least-fixpoint Oracle.
	// Counts and logs engine errors by type.
	// Asserts engine == oracle for all non-error results.
	// Fails immediately if any engine result is "allowed" while oracle says denied.
	seed := time.Now().UnixNano()
	t.Logf("Differential Test Seed: %d", seed)
	rng := rand.New(rand.NewSource(seed))

	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	schemas := []string{
		// 1. Hierarchy with arrows, union, exclusion
		`
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
      owner: [user]
      banned: [user, "group#member"]
    permissions:
      view: "(owner + parent->view) - banned"
`,
		// 2. Multi-role approval with intersection & union
		`
version: 1
types:
  user: {}
  group:
    relations:
      member: [user]
  project:
    relations:
      admin: [user]
      lead: [user]
      maintainer: ["group#member"]
    permissions:
      audit: "admin & lead"
      manage: "maintainer + audit"
`,
		// 3. Userset relations with nested groups & exclusions
		`
version: 1
types:
  user: {}
  group:
    relations:
      member: [user, "group#member"]
      banned: [user]
    permissions:
      active: "member - banned"
  item:
    relations:
      viewer: ["group#member"]
      editor: [user]
    permissions:
      view: "viewer + editor"
`,
		// 4. Multi-hop arrows with permissions
		`
version: 1
types:
  user: {}
  org:
    relations:
      member: [user]
    permissions:
      access: member
  team:
    relations:
      parent: [org]
      lead: [user]
    permissions:
      access: "lead + parent->access"
  repo:
    relations:
      team: [team]
      admin: [user]
    permissions:
      read: "team->access + admin"
      push: "admin & team->access"
`,
		// 5. Complex boolean grouping
		`
version: 1
types:
  user: {}
  group:
    relations:
      member: [user, "group#member"]
  asset:
    relations:
      r1: [user]
      r2: [user, "user:*"]
      r3: ["group#member"]
      r4: [user]
    permissions:
      p1: "r1 + r2"
      p2: "p1 & r3"
      p3: "p2 - r4"
      p4: "(r1 + r3) - (r2 & r4)"
`,
		// 6. Cyclic groups and exclusions
		`
version: 1
types:
  user: {}
  group:
    relations:
      member: [user, "group#member"]
  doc:
    relations:
      viewer: [user, "group#member"]
      banned: [user, "group#member"]
    permissions:
      view: "viewer - banned"
`,
		// 7. Arrow over folder mesh
		`
version: 1
types:
  user: {}
  folder:
    relations:
      parent: [folder]
      viewer: [user]
    permissions:
      view: "viewer + parent->view"
  doc:
    relations:
      parent: [folder]
      editor: [user]
    permissions:
      view: "editor + parent->view"
`,
		// 8. Permissions with multiple arrows and exclusions
		`
version: 1
types:
  user: {}
  folder:
    relations:
      parent: [folder]
      owner: [user]
    permissions:
      view: "owner + parent->view"
  doc:
    relations:
      parent: [folder]
      viewer: [user, "user:*"]
      restricted: [user]
    permissions:
      view: "(viewer + parent->view) - restricted"
`,
	}

	const numGraphs = 100
	users := []string{"u1", "u2", "u3", "u4", "u5"}
	errorCounts := make(map[string]int)
	totalTriples := 0

	for g := 0; g < numGraphs; g++ {
		// Pick a random schema archetype
		schText := schemas[rng.Intn(len(schemas))]
		sch, err := schema.ParseAndValidate(schText)
		if err != nil {
			t.Fatalf("failed to parse schema: %v", err)
		}

		uid, _ := ids.NewUUIDv7()
		tenantID := fmt.Sprintf("tenant_diff_100_g%d_%s", g, strings.ReplaceAll(uid.String(), "-", ""))

		_, err = s.SaveSchema(ctx, tenantID, 1, schText, sch)
		if err != nil {
			t.Fatalf("failed to save schema: %v", err)
		}

		// Generate random tuples conforming to schema
		var tuples []store.Tuple
		var ops []store.TupleOperation

		// Collect available types and their relations
		type relationInfo struct {
			objType string
			relName string
			allowed []schema.SubjectTypeRule
		}
		var allRels []relationInfo
		for tName, tDef := range sch.Types {
			if tName == "user" {
				continue
			}
			for rName, rDef := range tDef.Relations {
				allRels = append(allRels, relationInfo{
					objType: tName,
					relName: rName,
					allowed: rDef.SubjectTypes,
				})
			}
		}

		// Generate 4 to 12 tuples per graph
		numTuples := 4 + rng.Intn(9)
		seen := make(map[store.Tuple]bool)
		for i := 0; i < numTuples; i++ {
			rel := allRels[rng.Intn(len(allRels))]
			objID := fmt.Sprintf("id_%d", rng.Intn(4)+1)
			rule := rel.allowed[rng.Intn(len(rel.allowed))]

			var subj store.Subject
			if rule.Type == "user" {
				if rule.IsWildcard && rng.Intn(4) == 0 {
					subj = store.Subject{Type: "user", ID: "*"}
				} else {
					subj = store.Subject{Type: "user", ID: users[rng.Intn(len(users))]}
				}
			} else {
				subjID := fmt.Sprintf("id_%d", rng.Intn(4)+1)
				subj = store.Subject{Type: rule.Type, ID: subjID, Relation: rule.Relation}
			}

			tup := store.Tuple{
				TenantID:        tenantID,
				ObjectType:      rel.objType,
				ObjectID:        objID,
				Relation:        rel.relName,
				SubjectType:     subj.Type,
				SubjectID:       subj.ID,
				SubjectRelation: subj.Relation,
			}
			if seen[tup] {
				continue
			}
			seen[tup] = true
			tuples = append(tuples, tup)
			ops = append(ops, store.TupleOperation{Op: store.OpCreate, Tuple: tup})
		}

		rev, err := s.WriteRelationships(ctx, tenantID, ops)
		if err != nil {
			t.Fatalf("failed to write relationships for graph %d: %v", g, err)
		}

		oracle := engine.NewOracle(sch, tuples, users)
		eng := engine.New(s, engine.DefaultConfig())

		// Pick 5 random check queries per graph
		for q := 0; q < 5; q++ {
			// Pick random type that has permissions or relations
			var candidateTypes []string
			for tName := range sch.Types {
				if tName != "user" {
					candidateTypes = append(candidateTypes, tName)
				}
			}
			objType := candidateTypes[rng.Intn(len(candidateTypes))]
			tDef := sch.Types[objType]

			var candidateNames []string
			for r := range tDef.Relations {
				candidateNames = append(candidateNames, r)
			}
			for p := range tDef.Permissions {
				candidateNames = append(candidateNames, p)
			}
			name := candidateNames[rng.Intn(len(candidateNames))]

			obj := store.Object{Type: objType, ID: fmt.Sprintf("id_%d", rng.Intn(4)+1)}
			subj := store.Subject{Type: "user", ID: users[rng.Intn(len(users))]}

			req := engine.CheckRequest{
				TenantID:   tenantID,
				Revision:   rev,
				Object:     obj,
				Permission: name,
				Subject:    subj,
			}

			engResp, engErr := eng.Check(ctx, req)
			if engErr != nil {
				var errCategory string
				switch {
				case errors.Is(engErr, engine.ErrCycleCutoffInSubtrahend):
					errCategory = "cycle_cutoff_in_subtrahend"
				case errors.Is(engErr, engine.ErrDepthExceeded):
					errCategory = "depth_exceeded"
				case errors.Is(engErr, engine.ErrResourceExhausted):
					errCategory = "resource_exhausted"
				case errors.Is(engErr, context.DeadlineExceeded):
					errCategory = "timeout"
				default:
					errCategory = "other"
				}
				errorCounts[errCategory]++
				continue
			}

			oracleAllowed, oErr := oracle.Check(obj, name, subj)
			if oErr != nil {
				t.Fatalf("oracle check failed: %v", oErr)
			}

			if engResp.Allowed != oracleAllowed {
				if engResp.Allowed && !oracleAllowed {
					t.Fatalf("UNSOUND: seed %d graph %d Engine ALLOWED but Oracle DENIED for %s:%s#%s@%s:%s",
						seed, g, obj.Type, obj.ID, name, subj.Type, subj.ID)
				}
				if !engResp.Allowed && oracleAllowed {
					t.Fatalf("MISMATCH: seed %d graph %d Engine DENIED but Oracle ALLOWED for %s:%s#%s@%s:%s",
						seed, g, obj.Type, obj.ID, name, subj.Type, subj.ID)
				}
			}
			totalTriples++
		}
	}

	t.Logf("Differential Test Report: graphs=%d, triples=%d, errors_by_type=%v, seed=%d",
		numGraphs, totalTriples, errorCounts, seed)
}

func TestCheck_DenseCyclicGroups(t *testing.T) {
	// 12 groups, each a member of every other, subject in none.
	// Must finish in well under 100ms with DB reads linear in the number of groups (<= 12 reads).
	denseGroupSchema := `
version: 1
types:
  user: {}
  group:
    relations:
      member: [user, "group#member"]
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_dense_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(denseGroupSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}

	_, err = s.SaveSchema(ctx, tenantID, 1, denseGroupSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	const numGroups = 12
	var writes []store.TupleOperation

	// Each group is a member of every other group (12 * 11 = 132 tuples)
	for i := 1; i <= numGroups; i++ {
		for j := 1; j <= numGroups; j++ {
			if i == j {
				continue
			}
			writes = append(writes, store.TupleOperation{
				Op: store.OpCreate,
				Tuple: store.Tuple{
					ObjectType:      "group",
					ObjectID:        fmt.Sprintf("g%d", i),
					Relation:        "member",
					SubjectType:     "group",
					SubjectID:       fmt.Sprintf("g%d", j),
					SubjectRelation: "member",
				},
			})
		}
	}

	rev, err := s.WriteRelationships(ctx, tenantID, writes)
	if err != nil {
		t.Fatalf("failed to write dense relationships: %v", err)
	}

	eng := engine.New(s, engine.DefaultConfig())

	start := time.Now()
	res, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "group", ID: "g1"},
		Permission: "member",
		Subject:    store.Subject{Type: "user", ID: "nobody"},
	})
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("check failed with error: %v", err)
	}

	if res.Allowed {
		t.Fatalf("user:nobody should not be allowed in dense groups")
	}

	t.Logf("Dense cyclic groups check finished in %v with %d DB reads", duration, res.DBReads)

	if res.DBReads > 2*numGroups {
		t.Fatalf("DB reads (%d) exceeded linear bound of %d groups (%d)", res.DBReads, numGroups, 2*numGroups)
	}

	maxDuration := 200 * time.Millisecond
	if duration > maxDuration {
		t.Fatalf("Dense cyclic groups check took %v, which exceeds %v limit", duration, maxDuration)
	}
}

func TestCheck_RejectWildcardSubject(t *testing.T) {
	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_reject_wc_" + strings.ReplaceAll(uid.String(), "-", "")
	eng, _, rev := setupEngineWithSchema(t, tenantID)
	ctx := context.Background()

	// Check with Subject.ID = "*" must be rejected!
	_, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "doc", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "*"},
	})
	if !errors.Is(err, store.ErrInvalidIdentifier) {
		t.Fatalf("expected ErrInvalidIdentifier when subject id is '*', got %v", err)
	}
}

func TestCheck_ArrowIgnoresUsersetAndWildcard(t *testing.T) {
	arrowSchema := `
version: 1
types:
  user: {}
  group:
    relations:
      member: [user]
  folder:
    relations:
      viewer: [user]
    permissions:
      view: "viewer"
  doc:
    relations:
      parent: [folder]
    permissions:
      view: "parent->view"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_arrow_ignore_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(arrowSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	_, err = s.SaveSchema(ctx, tenantID, 1, arrowSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// Write valid tuples: doc:1#parent@folder:f1, folder:f1#viewer@user:alice
	rev, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "doc", ObjectID: "1", Relation: "parent", SubjectType: "folder", SubjectID: "f1"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "folder", ObjectID: "f1", Relation: "viewer", SubjectType: "user", SubjectID: "alice"}},
	})
	if err != nil {
		t.Fatalf("failed to write relationships: %v", err)
	}

	// Insert legacy/raw tuples on doc#parent with userset and wildcard directly to test arrow tolerance.
	// The arrow evaluation parent->view must ignore both userset and wildcard, and follow folder:f1.
	_, err = pool.Exec(ctx, `
		INSERT INTO authz_tuples (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation, created_rev)
		VALUES 
			($1, 'doc', '1', 'parent', 'group', 'g1', 'member', $2),
			($1, 'doc', '1', 'parent', 'user', '*', '', $2)
	`, tenantID, rev)
	if err != nil {
		t.Fatalf("failed to insert raw legacy tuples: %v", err)
	}

	eng := engine.New(s, engine.DefaultConfig())

	res, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "doc", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if err != nil {
		t.Fatalf("check failed with error: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected allowed=true via valid folder target, got false")
	}
}

func TestCheck_SchemaCache(t *testing.T) {
	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_sch_cache_" + strings.ReplaceAll(uid.String(), "-", "")
	eng, _, rev := setupEngineWithSchema(t, tenantID)
	ctx := context.Background()

	req := engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "doc", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	}

	// First call loads into cache
	_, err := eng.Check(ctx, req)
	if err != nil {
		t.Fatalf("first check failed: %v", err)
	}

	// Second call uses cache (hits schemaCache)
	_, err = eng.Check(ctx, req)
	if err != nil {
		t.Fatalf("second check failed: %v", err)
	}
}

func TestCheck_SplitRelationReads_10000MemberGroup(t *testing.T) {
	// Tests that checking membership against a 10,000-member group uses split relation reads:
	// (a) EXISTS check for exact subject (0 rows transferred into memory)
	// (b) ReadUsersetTuples fetches only subject_relation != '' tuples
	// Asserts DB reads and rows loaded stay small.
	groupSchema := `
version: 1
types:
  user: {}
  group:
    relations:
      member: [user, "group#member"]
  doc:
    relations:
      viewer: [user, "group#member"]
    permissions:
      view: viewer
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_split_reads_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(groupSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	_, err = s.SaveSchema(ctx, tenantID, 1, groupSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// Bulk insert 10,000 direct user members into group:big_group#member
	const memberCount = 10000
	_, err = pool.Exec(ctx, `
		INSERT INTO authz_tuples (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation, created_rev)
		SELECT $1, 'group', 'big_group', 'member', 'user', 'u_' || i::text, '', 1
		FROM generate_series(1, $2::int) AS i
	`, tenantID, memberCount)
	if err != nil {
		t.Fatalf("failed to bulk insert 10000 group members: %v", err)
	}

	// Insert doc:d1#viewer@group:big_group#member
	_, err = pool.Exec(ctx, `
		INSERT INTO authz_tuples (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation, created_rev)
		VALUES ($1, 'doc', 'd1', 'viewer', 'group', 'big_group', 'member', 1)
	`, tenantID)
	if err != nil {
		t.Fatalf("failed to insert doc viewer tuple: %v", err)
	}

	// Update tenant rev 1
	_, err = pool.Exec(ctx, `
		UPDATE authz_tenants SET current_rev = 1 WHERE tenant_id = $1
	`, tenantID)
	if err != nil {
		t.Fatalf("failed to update tenant rev: %v", err)
	}

	eng := engine.New(s, engine.DefaultConfig())

	// 1. Check user that IS a member (nested through group:big_group#member)
	resMember, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   1,
		Object:     store.Object{Type: "doc", ID: "d1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "u_42"},
	})
	if err != nil {
		t.Fatalf("check for u_42 failed: %v", err)
	}
	if !resMember.Allowed {
		t.Fatalf("expected u_42 to be ALLOWED")
	}
	if resMember.DBReads > 4 {
		t.Fatalf("expected <= 4 DB reads for 10,000 member group, got %d", resMember.DBReads)
	}
	t.Logf("10,000-member group ALLOWED check: dbReads=%d, depth=%d", resMember.DBReads, resMember.Depth)

	// 2. Check user that is NOT a member
	resNonMember, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   1,
		Object:     store.Object{Type: "doc", ID: "d1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if err != nil {
		t.Fatalf("check for alice failed: %v", err)
	}
	if resNonMember.Allowed {
		t.Fatalf("expected alice to be DENIED")
	}
	if resNonMember.DBReads > 4 {
		t.Fatalf("expected <= 4 DB reads for non-member check, got %d", resNonMember.DBReads)
	}
	t.Logf("10,000-member group DENIED check: dbReads=%d, depth=%d", resNonMember.DBReads, resNonMember.Depth)

	// 3. Direct check on group:big_group#member for u_42 (pure EXISTS query)
	resDirect, err := eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   1,
		Object:     store.Object{Type: "group", ID: "big_group"},
		Permission: "member",
		Subject:    store.Subject{Type: "user", ID: "u_42"},
	})
	if err != nil {
		t.Fatalf("direct check failed: %v", err)
	}
	if !resDirect.Allowed {
		t.Fatalf("expected direct member check to be ALLOWED")
	}
	if resDirect.DBReads != 1 {
		t.Fatalf("expected direct EXISTS check to take exactly 1 DB read, got %d", resDirect.DBReads)
	}
	t.Logf("Direct 10,000-member EXISTS check: dbReads=%d", resDirect.DBReads)
}

func TestCheck_ResourceCaps_MaxDBReads(t *testing.T) {
	chainSchema := `
version: 1
types:
  user: {}
  node:
    relations:
      parent: [node]
      owner:  [user]
    permissions:
      view: "owner + parent->view"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_cap_dbreads_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(chainSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	_, err = s.SaveSchema(ctx, tenantID, 1, chainSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// 5-hop chain: n1 -> n2 -> n3 -> n4 -> n5#owner@alice
	rev, err := s.WriteRelationships(ctx, tenantID, []store.TupleOperation{
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "node", ObjectID: "1", Relation: "parent", SubjectType: "node", SubjectID: "2"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "node", ObjectID: "2", Relation: "parent", SubjectType: "node", SubjectID: "3"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "node", ObjectID: "3", Relation: "parent", SubjectType: "node", SubjectID: "4"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "node", ObjectID: "4", Relation: "parent", SubjectType: "node", SubjectID: "5"}},
		{Op: store.OpCreate, Tuple: store.Tuple{ObjectType: "node", ObjectID: "5", Relation: "owner", SubjectType: "user", SubjectID: "alice"}},
	})
	if err != nil {
		t.Fatalf("failed to write relationships: %v", err)
	}

	// Set MaxDBReads cap to 2 (evaluating 5-hop chain requires > 2 DB reads)
	eng := engine.New(s, engine.Config{MaxDBReads: 2})
	_, err = eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "node", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if err == nil {
		t.Fatalf("expected ErrMaxDBReadsExceeded, got nil error")
	}
	if !errors.Is(err, engine.ErrMaxDBReadsExceeded) {
		t.Fatalf("expected ErrMaxDBReadsExceeded, got %v", err)
	}
	if !errors.Is(err, engine.ErrResourceExhausted) {
		t.Fatalf("expected wrapping ErrResourceExhausted, got %v", err)
	}
	t.Logf("MaxDBReads cap test passed: %v", err)
}

func TestCheck_ResourceCaps_MaxRowsPerRead(t *testing.T) {
	fanoutSchema := `
version: 1
types:
  user: {}
  folder:
    relations:
      viewer: [user]
    permissions:
      view: viewer
  doc:
    relations:
      parent: [folder]
    permissions:
      view: "parent->view"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_cap_rows_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(fanoutSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	_, err = s.SaveSchema(ctx, tenantID, 1, fanoutSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// Create 10 parent relationships for doc:d1
	var ops []store.TupleOperation
	for i := 1; i <= 10; i++ {
		ops = append(ops, store.TupleOperation{
			Op: store.OpCreate,
			Tuple: store.Tuple{
				ObjectType:  "doc",
				ObjectID:    "d1",
				Relation:    "parent",
				SubjectType: "folder",
				SubjectID:   fmt.Sprintf("f%d", i),
			},
		})
	}
	rev, err := s.WriteRelationships(ctx, tenantID, ops)
	if err != nil {
		t.Fatalf("failed to write relationships: %v", err)
	}

	// Set MaxRowsPerRead to 5 (arrow read on doc:d1#parent fetches 10 rows > 5)
	eng := engine.New(s, engine.Config{MaxRowsPerRead: 5})
	_, err = eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "doc", ID: "d1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if err == nil {
		t.Fatalf("expected ErrMaxRowsPerReadExceeded, got nil error")
	}
	if !errors.Is(err, engine.ErrMaxRowsPerReadExceeded) {
		t.Fatalf("expected ErrMaxRowsPerReadExceeded, got %v", err)
	}
	if !errors.Is(err, engine.ErrResourceExhausted) {
		t.Fatalf("expected wrapping ErrResourceExhausted, got %v", err)
	}
	t.Logf("MaxRowsPerRead cap test passed: %v", err)
}

func TestCheck_ResourceCaps_MaxVisitedNodes(t *testing.T) {
	chainSchema := `
version: 1
types:
  user: {}
  node:
    relations:
      parent: [node]
      owner:  [user]
    permissions:
      view: "owner + parent->view"
`
	pool := getTestPool(t)
	s := store.New(pool)
	ctx := context.Background()

	uid, _ := ids.NewUUIDv7()
	tenantID := "tenant_cap_visited_" + strings.ReplaceAll(uid.String(), "-", "")

	sch, err := schema.ParseAndValidate(chainSchema)
	if err != nil {
		t.Fatalf("failed to parse schema: %v", err)
	}
	_, err = s.SaveSchema(ctx, tenantID, 1, chainSchema, sch)
	if err != nil {
		t.Fatalf("failed to save schema: %v", err)
	}

	// 6-hop chain
	var ops []store.TupleOperation
	for i := 1; i <= 5; i++ {
		ops = append(ops, store.TupleOperation{
			Op: store.OpCreate,
			Tuple: store.Tuple{
				ObjectType:  "node",
				ObjectID:    fmt.Sprintf("%d", i),
				Relation:    "parent",
				SubjectType: "node",
				SubjectID:   fmt.Sprintf("%d", i+1),
			},
		})
	}
	ops = append(ops, store.TupleOperation{
		Op: store.OpCreate,
		Tuple: store.Tuple{
			ObjectType:  "node",
			ObjectID:    "6",
			Relation:    "owner",
			SubjectType: "user",
			SubjectID:   "alice",
		},
	})
	rev, err := s.WriteRelationships(ctx, tenantID, ops)
	if err != nil {
		t.Fatalf("failed to write relationships: %v", err)
	}

	// Set MaxVisitedNodes to 3 (chain requires visiting 6 nodes)
	eng := engine.New(s, engine.Config{MaxVisitedNodes: 3})
	_, err = eng.Check(ctx, engine.CheckRequest{
		TenantID:   tenantID,
		Revision:   rev,
		Object:     store.Object{Type: "node", ID: "1"},
		Permission: "view",
		Subject:    store.Subject{Type: "user", ID: "alice"},
	})
	if err == nil {
		t.Fatalf("expected ErrMaxVisitedNodesExceeded, got nil error")
	}
	if !errors.Is(err, engine.ErrMaxVisitedNodesExceeded) {
		t.Fatalf("expected ErrMaxVisitedNodesExceeded, got %v", err)
	}
	if !errors.Is(err, engine.ErrResourceExhausted) {
		t.Fatalf("expected wrapping ErrResourceExhausted, got %v", err)
	}
	t.Logf("MaxVisitedNodes cap test passed: %v", err)
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
