package engine

import (
	"errors"
	"fmt"

	"github.com/raviteja-core/keystone/internal/authz/schema"
	"github.com/raviteja-core/keystone/internal/authz/store"
)

// Oracle is a deliberately simple, in-memory reference implementation of Zanzibar permission checking.
// It has no concurrency, no database access, and no caching.
type Oracle struct {
	schema   *schema.Schema
	tuples   []store.Tuple
	maxDepth int
}

// NewOracle creates an in-memory test oracle.
func NewOracle(sch *schema.Schema, tuples []store.Tuple, maxDepth int) *Oracle {
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDepth
	}
	return &Oracle{
		schema:   sch,
		tuples:   tuples,
		maxDepth: maxDepth,
	}
}

// Check evaluates whether a subject has a permission on an object using a naive recursive search.
func (o *Oracle) Check(obj store.Object, perm string, subj store.Subject) (bool, error) {
	visiting := make(map[memoKey]bool)
	return o.eval(obj, perm, subj, 1, visiting)
}

func (o *Oracle) eval(obj store.Object, name string, subj store.Subject, depth int, visiting map[memoKey]bool) (bool, error) {
	if depth > o.maxDepth {
		return false, ErrDepthExceeded
	}

	key := memoKey{objectType: obj.Type, objectID: obj.ID, name: name}
	if visiting[key] {
		// Cycle contributes DENIED
		return false, nil
	}

	pathVisiting := make(map[memoKey]bool, len(visiting)+1)
	for k := range visiting {
		pathVisiting[k] = true
	}
	pathVisiting[key] = true

	typeDef, ok := o.schema.Types[obj.Type]
	if !ok {
		return false, fmt.Errorf("%w: %q", ErrUnknownType, obj.Type)
	}

	_, isRel := typeDef.Relations[name]
	permDef, isPerm := typeDef.Permissions[name]

	if !isRel && !isPerm {
		return false, fmt.Errorf("%w: %q on type %q", ErrUnknownRelationOrPermission, name, obj.Type)
	}

	if isRel {
		// Linear scan of in-memory tuples
		for _, t := range o.tuples {
			if t.ObjectType != obj.Type || t.ObjectID != obj.ID || t.Relation != name {
				continue
			}

			// Direct subject match
			if t.SubjectType == subj.Type && t.SubjectID == subj.ID && t.SubjectRelation == subj.Relation {
				return true, nil
			}
			// Wildcard subject match
			if t.SubjectType == subj.Type && t.SubjectID == "*" && subj.Relation == "" {
				return true, nil
			}
			// Userset subject match
			if t.SubjectRelation != "" {
				usersetObj := store.Object{Type: t.SubjectType, ID: t.SubjectID}
				allowed, err := o.eval(usersetObj, t.SubjectRelation, subj, depth+1, pathVisiting)
				if err != nil {
					return false, err
				}
				if allowed {
					return true, nil
				}
			}
		}
		return false, nil
	}

	// Permission expression
	return o.evalExpr(permDef.AST, obj, subj, depth, pathVisiting)
}

func (o *Oracle) evalExpr(node schema.Node, obj store.Object, subj store.Subject, depth int, visiting map[memoKey]bool) (bool, error) {
	switch n := node.(type) {
	case *schema.NameNode:
		return o.eval(obj, n.Name, subj, depth+1, visiting)

	case *schema.ArrowNode:
		for _, t := range o.tuples {
			if t.ObjectType != obj.Type || t.ObjectID != obj.ID || t.Relation != n.Relation {
				continue
			}
			targetObj := store.Object{Type: t.SubjectType, ID: t.SubjectID}
			allowed, err := o.eval(targetObj, n.Permission, subj, depth+1, visiting)
			if err != nil {
				return false, err
			}
			if allowed {
				return true, nil
			}
		}
		return false, nil

	case *schema.BinaryNode:
		switch n.Op {
		case schema.NodeUnion:
			left, err := o.evalExpr(n.Left, obj, subj, depth+1, visiting)
			if err != nil {
				return false, err
			}
			if left {
				return true, nil
			}
			return o.evalExpr(n.Right, obj, subj, depth+1, visiting)

		case schema.NodeIntersection:
			left, err := o.evalExpr(n.Left, obj, subj, depth+1, visiting)
			if err != nil {
				return false, err
			}
			if !left {
				return false, nil
			}
			return o.evalExpr(n.Right, obj, subj, depth+1, visiting)

		case schema.NodeExclusion:
			left, err := o.evalExpr(n.Left, obj, subj, depth+1, visiting)
			if err != nil {
				return false, err
			}
			if !left {
				return false, nil
			}
			right, err := o.evalExpr(n.Right, obj, subj, depth+1, visiting)
			if err != nil {
				return false, err
			}
			return !right, nil

		default:
			return false, errors.New("unknown binary operator in oracle")
		}

	default:
		return false, errors.New("unknown AST node in oracle")
	}
}
