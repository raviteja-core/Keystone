package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/raviteja-core/keystone/internal/authz/schema"
	"github.com/raviteja-core/keystone/internal/authz/store"
)

const (
	DefaultMaxDepth        = 25
	DefaultMaxConcurrency  = 16
	DefaultCheckTimeout    = 500 * time.Millisecond
	DefaultMaxDBReads      = 1000
	DefaultMaxRowsPerRead  = 1000
	DefaultMaxVisitedNodes = 5000
)

// Engine evaluates relationship-based access control checks with Zanzibar semantics.
type Engine struct {
	store             *store.Store
	maxDepth          int
	maxConcurrency    int
	timeout           time.Duration
	maxDBReads        int
	maxRowsPerRead    int
	maxVisitedNodes   int
	tenantSchemaCache sync.Map // keyed by tenantID, value *schema.Schema
}

// Config holds configuration options for the check engine.
type Config struct {
	MaxDepth        int
	MaxConcurrency  int
	Timeout         time.Duration
	MaxDBReads      int
	MaxRowsPerRead  int
	MaxVisitedNodes int
}

// DefaultConfig provides recommended defaults.
func DefaultConfig() Config {
	return Config{
		MaxDepth:        DefaultMaxDepth,
		MaxConcurrency:  DefaultMaxConcurrency,
		Timeout:         DefaultCheckTimeout,
		MaxDBReads:      DefaultMaxDBReads,
		MaxRowsPerRead:  DefaultMaxRowsPerRead,
		MaxVisitedNodes: DefaultMaxVisitedNodes,
	}
}

// New creates a new check engine.
func New(s *store.Store, cfg Config) *Engine {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = DefaultMaxDepth
	}
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = DefaultMaxConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultCheckTimeout
	}
	if cfg.MaxDBReads <= 0 {
		cfg.MaxDBReads = DefaultMaxDBReads
	}
	if cfg.MaxRowsPerRead <= 0 {
		cfg.MaxRowsPerRead = DefaultMaxRowsPerRead
	}
	if cfg.MaxVisitedNodes <= 0 {
		cfg.MaxVisitedNodes = DefaultMaxVisitedNodes
	}

	return &Engine{
		store:           s,
		maxDepth:        cfg.MaxDepth,
		maxConcurrency:  cfg.MaxConcurrency,
		timeout:         cfg.Timeout,
		maxDBReads:      cfg.MaxDBReads,
		maxRowsPerRead:  cfg.MaxRowsPerRead,
		maxVisitedNodes: cfg.MaxVisitedNodes,
	}
}

// InvalidateSchema removes a tenant's cached schema.
func (e *Engine) InvalidateSchema(tenantID string) {
	e.tenantSchemaCache.Delete(tenantID)
}

type memoKey struct {
	objectType string
	objectID   string
	name       string
}

type memoCache struct {
	mu sync.RWMutex
	m  map[memoKey]bool
}

func newMemoCache() *memoCache {
	return &memoCache{
		m: make(map[memoKey]bool),
	}
}

func (mc *memoCache) get(key memoKey) (bool, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	val, ok := mc.m[key]
	return val, ok
}

func (mc *memoCache) set(key memoKey, val bool) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.m[key] = val
}

type evalContext struct {
	ctx             context.Context
	tenantID        string
	revision        int64
	subject         store.Subject
	schema          *schema.Schema
	maxDepth        int
	maxDepthSeen    *atomic.Int64
	dbReads         *atomic.Int64
	visitedNodes    *atomic.Int64
	maxDBReads      int
	maxRowsPerRead  int
	maxVisitedNodes int
	dbSem           chan struct{}
	memo            *memoCache
}

func (c *evalContext) withContext(ctx context.Context) *evalContext {
	return &evalContext{
		ctx:             ctx,
		tenantID:        c.tenantID,
		revision:        c.revision,
		subject:         c.subject,
		schema:          c.schema,
		maxDepth:        c.maxDepth,
		maxDepthSeen:    c.maxDepthSeen,
		dbReads:         c.dbReads,
		visitedNodes:    c.visitedNodes,
		maxDBReads:      c.maxDBReads,
		maxRowsPerRead:  c.maxRowsPerRead,
		maxVisitedNodes: c.maxVisitedNodes,
		dbSem:           c.dbSem,
		memo:            c.memo,
	}
}

func (c *evalContext) updateDepth(d int) {
	for {
		curr := c.maxDepthSeen.Load()
		if int64(d) <= curr {
			break
		}
		if c.maxDepthSeen.CompareAndSwap(curr, int64(d)) {
			break
		}
	}
}

func cloneVisiting(v map[memoKey]bool) map[memoKey]bool {
	c := make(map[memoKey]bool, len(v)+1)
	for k := range v {
		c[k] = true
	}
	return c
}

func (e *Engine) loadSchema(ctx context.Context, tenantID string) (*schema.Schema, error) {
	if cached, ok := e.tenantSchemaCache.Load(tenantID); ok {
		return cached.(*schema.Schema), nil
	}

	sch, _, err := e.store.GetLatestSchema(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	e.tenantSchemaCache.Store(tenantID, sch)
	return sch, nil
}

// Check evaluates whether a subject has a permission on an object at a given revision.
func (e *Engine) Check(ctx context.Context, req CheckRequest) (*CheckResponse, error) {
	if req.TenantID == "" {
		return nil, store.ErrTenantNotFound
	}
	if !store.ValidateTypeOrRelation(req.Object.Type) {
		return nil, fmt.Errorf("%w: invalid object type %q", store.ErrInvalidIdentifier, req.Object.Type)
	}
	if !store.ValidateID(req.Object.ID, false) {
		return nil, fmt.Errorf("%w: invalid object id %q", store.ErrInvalidIdentifier, req.Object.ID)
	}
	if !store.ValidateTypeOrRelation(req.Permission) {
		return nil, fmt.Errorf("%w: invalid permission %q", store.ErrInvalidIdentifier, req.Permission)
	}
	if !store.ValidateTypeOrRelation(req.Subject.Type) {
		return nil, fmt.Errorf("%w: invalid subject type %q", store.ErrInvalidIdentifier, req.Subject.Type)
	}
	if req.Subject.ID == "*" || !store.ValidateID(req.Subject.ID, false) {
		return nil, fmt.Errorf("%w: subject id cannot be wildcard '*' or invalid %q", store.ErrInvalidIdentifier, req.Subject.ID)
	}

	evalCtxTimeout, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Load schema for tenant using versioned schema cache
	sch, err := e.loadSchema(evalCtxTimeout, req.TenantID)
	if err != nil {
		return nil, err
	}

	c := &evalContext{
		ctx:             evalCtxTimeout,
		tenantID:        req.TenantID,
		revision:        req.Revision,
		subject:         req.Subject,
		schema:          sch,
		maxDepth:        e.maxDepth,
		maxDepthSeen:    &atomic.Int64{},
		dbReads:         &atomic.Int64{},
		visitedNodes:    &atomic.Int64{},
		maxDBReads:      e.maxDBReads,
		maxRowsPerRead:  e.maxRowsPerRead,
		maxVisitedNodes: e.maxVisitedNodes,
		dbSem:           make(chan struct{}, e.maxConcurrency),
		memo:            newMemoCache(),
	}

	allowed, _, err := e.eval(c, req.Object, req.Permission, 1, make(map[memoKey]bool))
	if err != nil {
		return nil, err
	}

	return &CheckResponse{
		Allowed:  allowed,
		Revision: req.Revision,
		Depth:    int(c.maxDepthSeen.Load()),
		DBReads:  int(c.dbReads.Load()),
	}, nil
}

func (e *Engine) eval(c *evalContext, obj store.Object, name string, depth int, visiting map[memoKey]bool) (bool, bool, error) {
	if err := c.ctx.Err(); err != nil {
		return false, false, err
	}

	c.updateDepth(depth)
	if depth > c.maxDepth {
		return false, false, ErrDepthExceeded
	}
	if c.maxVisitedNodes > 0 && c.visitedNodes.Add(1) > int64(c.maxVisitedNodes) {
		return false, false, ErrMaxVisitedNodesExceeded
	}

	key := memoKey{objectType: obj.Type, objectID: obj.ID, name: name}

	// 1. Path-based cycle detection: If already visiting this (object, name) on the current path, return DENIED
	if visiting[key] {
		return false, true, nil
	}

	// 2. Check memo cache
	if val, ok := c.memo.get(key); ok {
		return val, false, nil
	}

	// 3. Mark current node on active path
	pathVisiting := cloneVisiting(visiting)
	pathVisiting[key] = true

	// 4. Look up definition in schema
	typeDef, ok := c.schema.Types[obj.Type]
	if !ok {
		return false, false, fmt.Errorf("%w: %q", ErrUnknownType, obj.Type)
	}

	_, isRel := typeDef.Relations[name]
	permDef, isPerm := typeDef.Permissions[name]

	if !isRel && !isPerm {
		return false, false, fmt.Errorf("%w: %q on type %q", ErrUnknownRelationOrPermission, name, obj.Type)
	}

	var allowed bool
	var hitCycle bool
	var err error

	if isRel {
		allowed, err := e.evalRelationBFS(c, obj, name, depth)
		if err != nil {
			return false, false, err
		}
		return allowed, false, nil
	}

	// Permission expression
	allowed, hitCycle, err = e.evalExpr(c, permDef.AST, obj, depth, pathVisiting)
	if err != nil {
		return false, false, err
	}

	// 5. Memoize ONLY if no cycle was hit on this branch
	if !hitCycle {
		c.memo.set(key, allowed)
	}

	return allowed, hitCycle, nil
}

func (e *Engine) evalExpr(c *evalContext, node schema.Node, obj store.Object, depth int, visiting map[memoKey]bool) (bool, bool, error) {
	if err := c.ctx.Err(); err != nil {
		return false, false, err
	}

	switch n := node.(type) {
	case *schema.NameNode:
		return e.eval(c, obj, n.Name, depth+1, visiting)

	case *schema.ArrowNode:
		// Arrow: for each tuple obj#relation@X, evaluate X#permission
		tuples, err := e.readTuplesWithSemaphore(c, store.TupleFilter{
			ObjectType: obj.Type,
			ObjectID:   obj.ID,
			Relation:   n.Relation,
		})
		if err != nil {
			return false, false, err
		}

		var hitCycle bool
		for _, t := range tuples {
			// Arrows only traverse direct object references.
			// Ignore tuples that have a userset subject or "*".
			if t.SubjectRelation != "" || t.SubjectID == "*" {
				continue
			}

			targetObj := store.Object{Type: t.SubjectType, ID: t.SubjectID}
			subAllowed, subCycle, subErr := e.eval(c, targetObj, n.Permission, depth+1, visiting)
			if subErr != nil {
				return false, false, subErr
			}
			if subAllowed {
				return true, subCycle, nil
			}
			if subCycle {
				hitCycle = true
			}
		}
		return false, hitCycle, nil

	case *schema.BinaryNode:
		switch n.Op {
		case schema.NodeUnion:
			return e.evalUnion(c, n.Left, n.Right, obj, depth, visiting)
		case schema.NodeIntersection:
			return e.evalIntersection(c, n.Left, n.Right, obj, depth, visiting)
		case schema.NodeExclusion:
			return e.evalExclusion(c, n.Left, n.Right, obj, depth, visiting)
		default:
			return false, false, fmt.Errorf("unknown binary operator: %s", n.Op)
		}

	default:
		return false, false, fmt.Errorf("unknown AST node: %T", node)
	}
}

type evalResult struct {
	allowed  bool
	hitCycle bool
	err      error
}

func (e *Engine) evalUnion(c *evalContext, left, right schema.Node, obj store.Object, depth int, visiting map[memoKey]bool) (bool, bool, error) {
	childCtx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	results := make(chan evalResult, 2)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				results <- evalResult{err: fmt.Errorf("evaluator panic: %v", r)}
			}
		}()
		childC := c.withContext(childCtx)
		a, hc, err := e.evalExpr(childC, left, obj, depth, visiting)
		results <- evalResult{allowed: a, hitCycle: hc, err: err}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				results <- evalResult{err: fmt.Errorf("evaluator panic: %v", r)}
			}
		}()
		childC := c.withContext(childCtx)
		a, hc, err := e.evalExpr(childC, right, obj, depth, visiting)
		results <- evalResult{allowed: a, hitCycle: hc, err: err}
	}()

	var hitCycle bool
	var firstErr error

	for i := 0; i < 2; i++ {
		res := <-results
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		if res.allowed {
			cancel() // short circuit on first ALLOWED
			return true, res.hitCycle, nil
		}
		if res.hitCycle {
			hitCycle = true
		}
	}

	if firstErr != nil {
		return false, false, firstErr
	}

	return false, hitCycle, nil
}

func (e *Engine) evalIntersection(c *evalContext, left, right schema.Node, obj store.Object, depth int, visiting map[memoKey]bool) (bool, bool, error) {
	childCtx, cancel := context.WithCancel(c.ctx)
	defer cancel()

	results := make(chan evalResult, 2)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				results <- evalResult{err: fmt.Errorf("evaluator panic: %v", r)}
			}
		}()
		childC := c.withContext(childCtx)
		a, hc, err := e.evalExpr(childC, left, obj, depth, visiting)
		results <- evalResult{allowed: a, hitCycle: hc, err: err}
	}()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				results <- evalResult{err: fmt.Errorf("evaluator panic: %v", r)}
			}
		}()
		childC := c.withContext(childCtx)
		a, hc, err := e.evalExpr(childC, right, obj, depth, visiting)
		results <- evalResult{allowed: a, hitCycle: hc, err: err}
	}()

	var hitCycle bool
	allowedCount := 0

	for i := 0; i < 2; i++ {
		res := <-results
		if res.err != nil {
			cancel()
			return false, false, res.err
		}
		if !res.allowed {
			cancel() // short circuit on first DENIED
			return false, res.hitCycle, nil
		}
		if res.hitCycle {
			hitCycle = true
		}
		allowedCount++
	}

	return allowedCount == 2, hitCycle, nil
}

func (e *Engine) evalExclusion(c *evalContext, left, right schema.Node, obj store.Object, depth int, visiting map[memoKey]bool) (bool, bool, error) {
	// Exclusion: Left must be ALLOWED and Right must be DENIED
	leftAllowed, leftCycle, leftErr := e.evalExpr(c, left, obj, depth, visiting)
	if leftErr != nil {
		return false, false, leftErr
	}

	// If Left is already not allowed, exclusion is false
	if !leftAllowed {
		return false, leftCycle, nil
	}

	rightAllowed, rightCycle, rightErr := e.evalExpr(c, right, obj, depth, visiting)
	if rightErr != nil {
		return false, false, rightErr
	}

	// Exclusion safety: If the subtrahend (right) evaluated to DENIED while having hit a cycle cut-off,
	// fail closed by returning an error so uncertain denials can never grant access.
	if !rightAllowed && rightCycle {
		return false, true, ErrCycleCutoffInSubtrahend
	}

	return !rightAllowed, leftCycle || rightCycle, nil
}

func (e *Engine) readTuplesWithSemaphore(c *evalContext, filter store.TupleFilter) ([]store.Tuple, error) {
	if c.maxDBReads > 0 && c.dbReads.Add(1) > int64(c.maxDBReads) {
		return nil, ErrMaxDBReadsExceeded
	}
	select {
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	case c.dbSem <- struct{}{}:
	}
	defer func() { <-c.dbSem }()

	tuples, err := e.store.ReadTuples(c.ctx, c.tenantID, filter, c.revision)
	if err != nil {
		return nil, err
	}
	if c.maxRowsPerRead > 0 && len(tuples) > c.maxRowsPerRead {
		return nil, ErrMaxRowsPerReadExceeded
	}
	return tuples, nil
}

func (e *Engine) checkSubjectExistsWithSemaphore(c *evalContext, obj store.Object, relation string, subject store.Subject) (bool, error) {
	if c.maxDBReads > 0 && c.dbReads.Add(1) > int64(c.maxDBReads) {
		return false, ErrMaxDBReadsExceeded
	}
	select {
	case <-c.ctx.Done():
		return false, c.ctx.Err()
	case c.dbSem <- struct{}{}:
	}
	defer func() { <-c.dbSem }()

	return e.store.CheckSubjectOrWildcardExists(c.ctx, c.tenantID, obj, relation, subject, c.revision)
}

func (e *Engine) readUsersetTuplesWithSemaphore(c *evalContext, obj store.Object, relation string) ([]store.Tuple, error) {
	if c.maxDBReads > 0 && c.dbReads.Add(1) > int64(c.maxDBReads) {
		return nil, ErrMaxDBReadsExceeded
	}
	select {
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	case c.dbSem <- struct{}{}:
	}
	defer func() { <-c.dbSem }()

	tuples, err := e.store.ReadUsersetTuples(c.ctx, c.tenantID, obj, relation, c.revision)
	if err != nil {
		return nil, err
	}
	if c.maxRowsPerRead > 0 && len(tuples) > c.maxRowsPerRead {
		return nil, ErrMaxRowsPerReadExceeded
	}
	return tuples, nil
}

type usersetNode struct {
	obj   store.Object
	rel   string
	depth int
}

func (e *Engine) evalRelationBFS(c *evalContext, startObj store.Object, startRel string, depth int) (bool, error) {
	startKey := memoKey{objectType: startObj.Type, objectID: startObj.ID, name: startRel}
	if val, ok := c.memo.get(startKey); ok {
		return val, nil
	}

	queue := []usersetNode{{obj: startObj, rel: startRel, depth: depth}}
	visited := make(map[memoKey]bool)
	visited[startKey] = true

	for len(queue) > 0 {
		if err := c.ctx.Err(); err != nil {
			return false, err
		}

		curr := queue[0]
		queue = queue[1:]

		c.updateDepth(curr.depth)
		if curr.depth > c.maxDepth {
			return false, ErrDepthExceeded
		}
		if c.maxVisitedNodes > 0 && c.visitedNodes.Add(1) > int64(c.maxVisitedNodes) {
			return false, ErrMaxVisitedNodesExceeded
		}

		// (a) Fast EXISTS check for exact subject or type wildcard
		exists, err := e.checkSubjectExistsWithSemaphore(c, curr.obj, curr.rel, c.subject)
		if err != nil {
			return false, err
		}
		if exists {
			c.memo.set(startKey, true)
			return true, nil
		}

		// (b) Fetch only userset-subject tuples
		usersets, err := e.readUsersetTuplesWithSemaphore(c, curr.obj, curr.rel)
		if err != nil {
			return false, err
		}

		for _, t := range usersets {
			nextObj := store.Object{Type: t.SubjectType, ID: t.SubjectID}
			nextKey := memoKey{objectType: nextObj.Type, objectID: nextObj.ID, name: t.SubjectRelation}

			if val, ok := c.memo.get(nextKey); ok && val {
				c.memo.set(startKey, true)
				return true, nil
			}

			if !visited[nextKey] {
				visited[nextKey] = true
				queue = append(queue, usersetNode{
					obj:   nextObj,
					rel:   t.SubjectRelation,
					depth: curr.depth + 1,
				})
			}
		}
	}

	c.memo.set(startKey, false)
	return false, nil
}
