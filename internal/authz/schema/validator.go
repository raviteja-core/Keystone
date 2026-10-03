package schema

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	MaxTypesLimit = 64
)

var (
	ErrUnsupportedVersion = errors.New("unsupported schema version: only version 1 is supported")
	ErrTooManyTypes       = errors.New("schema exceeds maximum limit of 64 types")
	ErrNoTypes            = errors.New("schema must contain at least one type")
	ErrNameCollision      = errors.New("relation and permission name collision")
	ErrUnknownType        = errors.New("unknown object type")
	ErrUnknownRelation    = errors.New("unknown relation")
	ErrUnknownPermission  = errors.New("unknown permission")
	ErrInvalidArrow       = errors.New("invalid arrow expression")
	ErrPermissionCycle    = errors.New("permission cycle detected")
)

// ValidateRawSchema validates and compiles a raw parsed schema structure.
func ValidateRawSchema(raw *RawSchema) (*Schema, error) {
	if raw.Version != 1 {
		return nil, fmt.Errorf("%w: got %d", ErrUnsupportedVersion, raw.Version)
	}

	if len(raw.Types) == 0 {
		return nil, ErrNoTypes
	}

	if len(raw.Types) > MaxTypesLimit {
		return nil, fmt.Errorf("%w: got %d types (max %d)", ErrTooManyTypes, len(raw.Types), MaxTypesLimit)
	}

	compiled := &Schema{
		Version: raw.Version,
		Types:   make(map[string]*TypeDefinition, len(raw.Types)),
	}

	// 1. First pass: Validate type names and register type skeletons
	for typeName := range raw.Types {
		if !ValidateIdentifier(typeName) {
			return nil, fmt.Errorf("%w: invalid type name %q", ErrInvalidIdentifier, typeName)
		}
		compiled.Types[typeName] = &TypeDefinition{
			Name:        typeName,
			Relations:   make(map[string]*RelationDefinition),
			Permissions: make(map[string]*PermissionDefinition),
		}
	}

	// 2. Second pass: Validate relations and parse subject type rules
	for typeName, rawType := range raw.Types {
		typeDef := compiled.Types[typeName]

		for relName, rawRules := range rawType.Relations {
			if !ValidateIdentifier(relName) {
				return nil, fmt.Errorf("%w: invalid relation name %q on type %q", ErrInvalidIdentifier, relName, typeName)
			}

			// Check relation/permission collision
			if _, exists := rawType.Permissions[relName]; exists {
				return nil, fmt.Errorf("%w: name %q on type %q is defined as both relation and permission", ErrNameCollision, relName, typeName)
			}

			rules := make([]SubjectTypeRule, 0, len(rawRules))
			for _, ruleStr := range rawRules {
				rule, err := ParseSubjectTypeRule(ruleStr)
				if err != nil {
					return nil, fmt.Errorf("type %q relation %q: %w", typeName, relName, err)
				}

				// Target type must exist
				targetTypeDef, ok := compiled.Types[rule.Type]
				if !ok {
					return nil, fmt.Errorf("%w %q referenced in type %q relation %q", ErrUnknownType, rule.Type, typeName, relName)
				}

				// If userset (group#member), the target relation must exist on target type
				if rule.Relation != "" {
					targetRawType := raw.Types[rule.Type]
					if _, hasRel := targetRawType.Relations[rule.Relation]; !hasRel {
						return nil, fmt.Errorf("%w: userset relation %q does not exist on type %q (referenced by type %q relation %q)",
							ErrUnknownRelation, rule.Relation, rule.Type, typeName, relName)
					}
				}

				_ = targetTypeDef
				rules = append(rules, rule)
			}

			typeDef.Relations[relName] = &RelationDefinition{
				Name:         relName,
				SubjectTypes: rules,
			}
		}
	}

	// 3. Third pass: Parse permission expressions into AST
	for typeName, rawType := range raw.Types {
		typeDef := compiled.Types[typeName]

		for permName, exprStr := range rawType.Permissions {
			if !ValidateIdentifier(permName) {
				return nil, fmt.Errorf("%w: invalid permission name %q on type %q", ErrInvalidIdentifier, permName, typeName)
			}

			if _, exists := typeDef.Relations[permName]; exists {
				return nil, fmt.Errorf("%w: name %q on type %q is defined as both relation and permission", ErrNameCollision, permName, typeName)
			}

			ast, err := ParseExpression(exprStr)
			if err != nil {
				return nil, fmt.Errorf("syntax error in permission %q on type %q: %w", permName, typeName, err)
			}

			typeDef.Permissions[permName] = &PermissionDefinition{
				Name:       permName,
				Expression: exprStr,
				AST:        ast,
			}
		}
	}

	// 4. Fourth pass: Semantic validation of AST nodes (names and arrows)
	for typeName, typeDef := range compiled.Types {
		for permName, permDef := range typeDef.Permissions {
			if err := validateAST(compiled, typeDef, permDef.AST); err != nil {
				return nil, fmt.Errorf("type %q permission %q: %w", typeName, permName, err)
			}
		}
	}

	// 5. Fifth pass: Permission cycle detection on the same object (DFS)
	for _, typeDef := range compiled.Types {
		if err := detectPermissionCycles(typeDef); err != nil {
			return nil, err
		}
	}

	return compiled, nil
}

// validateAST recursively validates names and arrows in an expression AST.
func validateAST(schema *Schema, currentType *TypeDefinition, node Node) error {
	switch n := node.(type) {
	case *NameNode:
		// Name must exist on the current type as either a relation or a permission
		_, isRel := currentType.Relations[n.Name]
		_, isPerm := currentType.Permissions[n.Name]
		if !isRel && !isPerm {
			return fmt.Errorf("%w: %q on type %q is neither a relation nor a permission", ErrUnknownPermission, n.Name, currentType.Name)
		}
		return nil

	case *ArrowNode:
		// Left side must be a relation on the current type
		relDef, isRel := currentType.Relations[n.Relation]
		if !isRel {
			if _, isPerm := currentType.Permissions[n.Relation]; isPerm {
				return fmt.Errorf("%w: arrow left side %q on type %q is a permission; must be a relation", ErrInvalidArrow, n.Relation, currentType.Name)
			}
			return fmt.Errorf("%w: arrow left side relation %q does not exist on type %q", ErrUnknownRelation, n.Relation, currentType.Name)
		}

		if len(relDef.SubjectTypes) == 0 {
			return fmt.Errorf("%w: arrow relation %q on type %q has no allowed subject types", ErrInvalidArrow, n.Relation, currentType.Name)
		}

		// Arrow left side relation subject types must be plain object types (not userset, not wildcard)
		for _, rule := range relDef.SubjectTypes {
			if rule.IsWildcard {
				return fmt.Errorf("%w: arrow left side relation %q on type %q allows wildcard %q; arrows require plain object subject types",
					ErrInvalidArrow, n.Relation, currentType.Name, rule.String())
			}
			if rule.Relation != "" {
				return fmt.Errorf("%w: arrow left side relation %q on type %q allows userset %q; arrows require plain object subject types",
					ErrInvalidArrow, n.Relation, currentType.Name, rule.String())
			}

			// Target object type must have the permission (or relation)
			targetType, ok := schema.Types[rule.Type]
			if !ok {
				return fmt.Errorf("%w %q referenced by relation %q", ErrUnknownType, rule.Type, n.Relation)
			}

			_, hasPerm := targetType.Permissions[n.Permission]
			_, hasRel := targetType.Relations[n.Permission]
			if !hasPerm && !hasRel {
				return fmt.Errorf("%w: arrow target %q does not exist on type %q", ErrUnknownPermission, n.Permission, rule.Type)
			}
		}
		return nil

	case *BinaryNode:
		if err := validateAST(schema, currentType, n.Left); err != nil {
			return err
		}
		return validateAST(schema, currentType, n.Right)

	default:
		return fmt.Errorf("unknown AST node type: %T", node)
	}
}

// detectPermissionCycles uses DFS with 3-color node state to detect permission cycles on the same object.
func detectPermissionCycles(typeDef *TypeDefinition) error {
	const (
		white = 0 // unvisited
		gray  = 1 // currently visiting in call stack
		black = 2 // finished
	)

	// Build adjacency list of permission dependencies on the same object
	adj := make(map[string][]string, len(typeDef.Permissions))
	for permName, permDef := range typeDef.Permissions {
		var deps []string
		collectPermissionDeps(permDef.AST, typeDef, &deps)
		adj[permName] = deps
	}

	state := make(map[string]int, len(typeDef.Permissions))
	var path []string

	var dfs func(u string) error
	dfs = func(u string) error {
		state[u] = gray
		path = append(path, u)

		// Sort dependencies for deterministic cycle paths in errors
		neighbors := adj[u]
		sort.Strings(neighbors)

		for _, v := range neighbors {
			if state[v] == gray {
				// Found cycle: reconstruct cycle path
				cycleStart := -1
				for i, p := range path {
					if p == v {
						cycleStart = i
						break
					}
				}
				cyclePath := append([]string{}, path[cycleStart:]...)
				cyclePath = append(cyclePath, v)
				return fmt.Errorf("%w on type %q: %s", ErrPermissionCycle, typeDef.Name, strings.Join(cyclePath, " -> "))
			}
			if state[v] == white {
				if err := dfs(v); err != nil {
					return err
				}
			}
		}

		path = path[:len(path)-1]
		state[u] = black
		return nil
	}

	// Deterministic traversal order
	permNames := make([]string, 0, len(typeDef.Permissions))
	for name := range typeDef.Permissions {
		permNames = append(permNames, name)
	}
	sort.Strings(permNames)

	for _, name := range permNames {
		if state[name] == white {
			if err := dfs(name); err != nil {
				return err
			}
		}
	}

	return nil
}

// collectPermissionDeps extracts references to permissions on the same object.
func collectPermissionDeps(node Node, typeDef *TypeDefinition, deps *[]string) {
	switch n := node.(type) {
	case *NameNode:
		// If it refers to a permission on the same type, add dependency
		if _, isPerm := typeDef.Permissions[n.Name]; isPerm {
			*deps = append(*deps, n.Name)
		}
	case *BinaryNode:
		collectPermissionDeps(n.Left, typeDef, deps)
		collectPermissionDeps(n.Right, typeDef, deps)
	case *ArrowNode:
		// Arrows jump across relations to other objects; they do not introduce cycles on the same object
	}
}
