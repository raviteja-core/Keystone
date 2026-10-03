package engine

import (
	"fmt"

	"github.com/raviteja-core/keystone/internal/authz/schema"
	"github.com/raviteja-core/keystone/internal/authz/store"
)

// Oracle is an independent reference implementation of Zanzibar permission checking
// using bottom-up least-fixpoint closure. It does not use recursion, path pruning,
// depth limits, concurrency, or database access.
type Oracle struct {
	schema *schema.Schema
	tuples []store.Tuple
	facts  map[Fact]bool
}

// Fact represents a single ground derivation: (subject, object, relation_or_permission).
type Fact struct {
	SubjectType     string
	SubjectID       string
	SubjectRelation string
	ObjectType      string
	ObjectID        string
	Name            string
}

// NewOracle creates an in-memory test oracle and computes the least-fixpoint closure
// over all objects, relations, permissions, and subjects.
func NewOracle(sch *schema.Schema, tuples []store.Tuple, knownUsers []string) *Oracle {
	o := &Oracle{
		schema: sch,
		tuples: tuples,
		facts:  make(map[Fact]bool),
	}
	o.computeFixpoint(knownUsers)
	return o
}

func (o *Oracle) computeFixpoint(knownUsers []string) {
	// 1. Collect all distinct objects and concrete subjects in the universe
	objects := make(map[store.Object]bool)
	subjects := make(map[store.Subject]bool)

	for _, u := range knownUsers {
		subjects[store.Subject{Type: "user", ID: u}] = true
	}

	for _, t := range o.tuples {
		objects[store.Object{Type: t.ObjectType, ID: t.ObjectID}] = true
		if t.SubjectType != "" && t.SubjectID != "" && t.SubjectID != "*" {
			subjects[store.Subject{
				Type:     t.SubjectType,
				ID:       t.SubjectID,
				Relation: t.SubjectRelation,
			}] = true
			if t.SubjectRelation != "" {
				objects[store.Object{Type: t.SubjectType, ID: t.SubjectID}] = true
			}
		}
	}

	// 2. Seed base facts from direct and wildcard tuples
	for _, t := range o.tuples {
		if t.SubjectID == "*" && t.SubjectRelation == "" {
			// Wildcard grants to all known users of that type
			for _, u := range knownUsers {
				if t.SubjectType == "user" {
					o.facts[Fact{
						SubjectType: "user",
						SubjectID:   u,
						ObjectType:  t.ObjectType,
						ObjectID:    t.ObjectID,
						Name:        t.Relation,
					}] = true
				}
			}
		} else if t.SubjectRelation == "" {
			// Direct subject
			o.facts[Fact{
				SubjectType: t.SubjectType,
				SubjectID:   t.SubjectID,
				ObjectType:  t.ObjectType,
				ObjectID:    t.ObjectID,
				Name:        t.Relation,
			}] = true
		}
	}

	// 3. Bottom-up fixpoint iteration
	// Iteratively derive new facts until reaching the least fixpoint (no change)
	maxIterations := 200
	for iter := 0; iter < maxIterations; iter++ {
		changed := false

		for obj := range objects {
			typeDef, ok := o.schema.Types[obj.Type]
			if !ok {
				continue
			}

			// A. Userset closure on relations
			for _, t := range o.tuples {
				if t.ObjectType != obj.Type || t.ObjectID != obj.ID || t.SubjectRelation == "" {
					continue
				}

				usersetObj := store.Object{Type: t.SubjectType, ID: t.SubjectID}
				for s := range subjects {
					if s.Relation != "" {
						continue // only evaluate concrete users/subjects
					}
					// If s has t.SubjectRelation on usersetObj, then s has t.Relation on obj
					if o.facts[Fact{
						SubjectType: s.Type,
						SubjectID:   s.ID,
						ObjectType:  usersetObj.Type,
						ObjectID:    usersetObj.ID,
						Name:        t.SubjectRelation,
					}] {
						f := Fact{
							SubjectType: s.Type,
							SubjectID:   s.ID,
							ObjectType:  obj.Type,
							ObjectID:    obj.ID,
							Name:        t.Relation,
						}
						if !o.facts[f] {
							o.facts[f] = true
							changed = true
						}
					}
				}
			}

			// B. Permission rules
			for permName, permDef := range typeDef.Permissions {
				for s := range subjects {
					if s.Relation != "" {
						continue
					}
					f := Fact{
						SubjectType: s.Type,
						SubjectID:   s.ID,
						ObjectType:  obj.Type,
						ObjectID:    obj.ID,
						Name:        permName,
					}
					if o.facts[f] {
						continue
					}

					if o.evalAST(permDef.AST, obj, s) {
						o.facts[f] = true
						changed = true
					}
				}
			}
		}

		if !changed {
			break
		}
	}
}

func (o *Oracle) evalAST(node schema.Node, obj store.Object, s store.Subject) bool {
	switch n := node.(type) {
	case *schema.NameNode:
		return o.facts[Fact{
			SubjectType: s.Type,
			SubjectID:   s.ID,
			ObjectType:  obj.Type,
			ObjectID:    obj.ID,
			Name:        n.Name,
		}]

	case *schema.ArrowNode:
		// Arrow: exists t in tuples such that obj#n.Relation@target and target#n.Permission holds for s
		for _, t := range o.tuples {
			if t.ObjectType == obj.Type && t.ObjectID == obj.ID && t.Relation == n.Relation {
				if t.SubjectRelation != "" || t.SubjectID == "*" {
					continue // arrows traverse direct objects only
				}
				if o.facts[Fact{
					SubjectType: s.Type,
					SubjectID:   s.ID,
					ObjectType:  t.SubjectType,
					ObjectID:    t.SubjectID,
					Name:        n.Permission,
				}] {
					return true
				}
			}
		}
		return false

	case *schema.BinaryNode:
		switch n.Op {
		case schema.NodeUnion:
			return o.evalAST(n.Left, obj, s) || o.evalAST(n.Right, obj, s)
		case schema.NodeIntersection:
			return o.evalAST(n.Left, obj, s) && o.evalAST(n.Right, obj, s)
		case schema.NodeExclusion:
			return o.evalAST(n.Left, obj, s) && !o.evalAST(n.Right, obj, s)
		default:
			return false
		}

	default:
		return false
	}
}

// Check evaluates whether a subject has a permission on an object by direct lookup in the fixpoint facts.
func (o *Oracle) Check(obj store.Object, perm string, subj store.Subject) (bool, error) {
	typeDef, ok := o.schema.Types[obj.Type]
	if !ok {
		return false, fmt.Errorf("%w: %q", ErrUnknownType, obj.Type)
	}

	_, isRel := typeDef.Relations[perm]
	_, isPerm := typeDef.Permissions[perm]
	if !isRel && !isPerm {
		return false, fmt.Errorf("%w: %q on type %q", ErrUnknownRelationOrPermission, perm, obj.Type)
	}

	return o.facts[Fact{
		SubjectType: subj.Type,
		SubjectID:   subj.ID,
		ObjectType:  obj.Type,
		ObjectID:    obj.ID,
		Name:        perm,
	}], nil
}
