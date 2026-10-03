# Phase 2 Learning Notes: Building a Google Zanzibar-Style Authorization Engine

## 1. What is Relationship-Based Access Control (ReBAC)?

Traditional access control models—Access Control Lists (ACLs) and Role-Based Access Control (RBAC)—collapse under the weight of real-world multi-tenant software:
- **ACLs** attach allowed users directly to every object. When a group of 5,000 members changes, every resource ACL in the system must be updated.
- **RBAC** introduces global or organization roles (`ADMIN`, `VIEWER`), but cannot naturally model resource hierarchies (e.g. "a user who can view a folder can view all nested files within it") or dynamic resource ownership without custom business logic strewn across application handlers.

Google Zanzibar solved this with **Relationship-Based Access Control (ReBAC)**: access is not an assigned attribute; it is a **reachability query over a directed relationship graph**.

Every permission check answers the question:
> *Is there a valid path in the graph from subject $S$ to permission $P$ on object $O$?*

---

## 2. Core Concepts & Data Model

Keystone implements the foundational Zanzibar primitives:

### Objects, Relations, and Subjects
- **Object:** A typed resource entity identified as `type:id` (e.g., `doc:readme`, `folder:engineering`).
- **Relation:** A named directed edge between entities (e.g., `owner`, `parent`, `member`).
- **Subject:** Can be:
  1. A concrete user: `user:alice`
  2. A type wildcard: `user:*` (represents any authenticated user of that type)
  3. A userset: `group:devs#member` (refers to the set of all subjects who have relation `member` on `group:devs`)

### Relationship Tuples
All facts in Keystone are stored in PostgreSQL table `authz_tuples` as normalized, append-only tuples:
$$\langle \text{tenant\_id}, \text{object\_type}, \text{object\_id}, \text{relation}, \text{subject\_type}, \text{subject\_id}, \text{subject\_relation}, \text{created\_rev}, \text{deleted\_rev} \rangle$$

Deletions do not destroy rows; they set `deleted_rev`, enabling exact point-in-time snapshot reads.

---

## 3. The Keystone Schema Language

Instead of hardcoding graph traversal rules in Go code, Keystone uses a declarative YAML schema language:

```yaml
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
      banned: [user, "group#member"]
    permissions:
      edit: "owner + editor"
      view: "(edit + parent->view) - banned"
```

### Expression Grammar
Permissions are composed using a formal grammar with strict precedence:
1. **Name Reference (`ref`):** Inherits an existing relation or another permission on the same object.
2. **Arrow Operator (`rel->perm`):** Tuple-to-userset rewrite. For each tuple `doc:1#parent@folder:F`, evaluate `folder:F#perm`.
3. **Union (`+`):** Allowed if *either* left or right branch allows access. Evaluated concurrently with early short-circuiting on the first `ALLOWED`.
4. **Intersection (`&`):** Allowed if and only if *both* left and right branches allow access. Evaluated concurrently with early short-circuiting on the first `DENIED`.
5. **Exclusion (`-`):** Subtraction / deny-lists. Allowed if left is `ALLOWED` *and* right is `DENIED`.

---

## 4. Graph Traversal, Cycles, and Concurrency

Graph traversal in a distributed ReBAC engine presents three major engineering pitfalls:

### 1. Cycle Safety & Memoization Poisoning
If group A includes group B, and group B includes group A ($A \leftrightarrow B$), a naive DFS enters an infinite loop.
- **Path-based Cycle Detection:** Keystone tracks the set of `(object, name)` nodes currently being evaluated on the active call stack path. If a node is encountered that already exists on the current stack, that branch immediately returns `DENIED` with `hitCycle = true`.
- **Preventing Cache Poisoning:** A sub-result can only be cached in the per-request memoization table if its evaluation path **never encountered a cycle cut-off** (`!hitCycle`). Otherwise, a path-dependent cut-off returning `DENIED` would poison the cache, incorrectly denying a subsequent clean path to the same node.

### 2. Exclusion Subtrahend Safety
In `view = viewer - banned`, if the evaluation of `banned` hits a cycle cut-off, what should happen?
- If `banned` cut-off returned `DENIED` (not banned), the exclusion $A - B$ would treat the user as *not banned* and grant access!
- **Keystone's Defense:** In an exclusion subtrahend ($B$), any cycle cut-off aborts evaluation and **fails closed** with `ErrCycleCutoffInSubtrahend`. Security always takes precedence over partial evaluation.

### 3. BFS Closure for Userset Relations
Pure userset relations (`group:A#member@group:B#member`) form directed union graphs without arrows or subtractions.
Keystone evaluates userset relations using an iterative **Breadth-First Search (BFS)** with a global `visited` set. This guarantees:
- Cycle tolerance without cycle cut-offs (`hitCycle` is always false, safe to memoize).
- Linear DB reads $O(N)$ bounded by the number of groups in dense cyclic meshes.

### 4. Split Relation Reads for Scale
If a group has 10,000 direct user members, reading all tuples into memory to check if Alice is a member wastes network bandwidth and memory.
Keystone splits relation evaluation into:
1. `CheckSubjectOrWildcardExists`: An indexed PostgreSQL `SELECT EXISTS (...)` query that checks for the exact user or wildcard. Zero rows are loaded into application memory.
2. `ReadUsersetTuples`: A query that retrieves **only** tuples where `subject_relation != ''` (pointing to nested groups).
In a group of 10,000 members, evaluating access takes $\le 4$ DB reads and transfers $\le 1$ row across the wire.

### 5. Resource Caps & Bounded Concurrency
To prevent denial-of-service from adversarial graphs, Keystone enforces:
- `MaxDepth` (default 25 object transitions): Exceeding returns `ErrDepthExceeded`.
- `MaxDBReads` (default 1000): Exceeding returns `ErrMaxDBReadsExceeded`.
- `MaxRowsPerRead` (default 1000): Exceeding returns `ErrMaxRowsPerReadExceeded`.
- `MaxVisitedNodes` (default 5000): Exceeding returns `ErrMaxVisitedNodesExceeded`.
All resource cap violations wrap `ErrResourceExhausted`.
To eliminate starvation, Keystone uses a concurrency semaphore only around I/O operations (DB queries), never holding locks across recursive evaluator child invocations.

---

## 5. Formal Verification: Differential Testing with Least-Fixpoint Oracle

How do you prove that an asynchronous, multi-threaded, short-circuiting, memoizing graph engine is semantically sound?
**By differential testing against an independent mathematical oracle.**

In `internal/authz/engine/oracle.go`, we implemented an independent Zanzibar reference engine using **bottom-up least-fixpoint closure**:
- It contains no concurrency, no goroutines, no path pruning, no memo caches, and no database queries.
- It iterates over the universe of objects and subjects, computing the fixpoint of the inference rules until no new facts can be derived.
- In `TestDifferential_RandomSchemasAndGraphs_100Runs`, we run 100 randomized graphs with 8 diverse randomized schema archetypes (unions, intersections, exclusions, arrows, cyclic groups, wildcards), asserting that every single non-error decision of the production engine exactly equals the Oracle.

---

## 6. Consistency & The Zookie

Zanzibar prevents the "New Enemy" problem (where a revoked permission is resurrected due to stale replication lag) using **Zookies**:
- A Zookie is an opaque base64url token (e.g. `v1.eyJ0IjoidGVuYW50MSIsInIiOjQyfQ`) encoding the tenant ID and the monotonically increasing database transaction revision.
- Every write returns a Zookie representing the exact transaction revision of that write.
- Subsequent read or check requests provide the Zookie under `at_least_as_fresh` consistency mode. The server ensures the evaluation is performed at a revision $\ge$ the Zookie's revision.
- **Tenant Isolation:** The Zookie cryptographically binds the tenant ID. If a client attempts to present Tenant A's Zookie to Tenant B's API, the request is immediately rejected with `ErrZookieTenantMismatch`.
