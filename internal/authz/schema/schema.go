package schema

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var identRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ValidateIdentifier checks if a name matches [a-z][a-z0-9_]{0,63}.
func ValidateIdentifier(name string) bool {
	return identRegex.MatchString(name)
}

// SubjectTypeRule specifies an allowed subject type for a relation.
type SubjectTypeRule struct {
	Type       string `json:"type"`                  // Object type, e.g. "user", "group"
	Relation   string `json:"relation,omitempty"`    // Userset relation, e.g. "member" or ""
	IsWildcard bool   `json:"is_wildcard,omitempty"` // True if "user:*"
}

func (s SubjectTypeRule) String() string {
	if s.IsWildcard {
		return s.Type + ":*"
	}
	if s.Relation != "" {
		return s.Type + "#" + s.Relation
	}
	return s.Type
}

// ParseSubjectTypeRule parses strings like "user", "group#member", "user:*".
func ParseSubjectTypeRule(raw string) (SubjectTypeRule, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return SubjectTypeRule{}, errors.New("empty subject type rule")
	}

	if strings.HasSuffix(raw, ":*") {
		objType := strings.TrimSuffix(raw, ":*")
		if !ValidateIdentifier(objType) {
			return SubjectTypeRule{}, fmt.Errorf("%w: invalid wildcard subject type %q", ErrInvalidIdentifier, objType)
		}
		return SubjectTypeRule{
			Type:       objType,
			IsWildcard: true,
		}, nil
	}

	if strings.Contains(raw, "#") {
		parts := strings.Split(raw, "#")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return SubjectTypeRule{}, fmt.Errorf("%w: invalid userset subject rule %q", ErrInvalidIdentifier, raw)
		}
		if !ValidateIdentifier(parts[0]) {
			return SubjectTypeRule{}, fmt.Errorf("%w: invalid userset object type %q", ErrInvalidIdentifier, parts[0])
		}
		if !ValidateIdentifier(parts[1]) {
			return SubjectTypeRule{}, fmt.Errorf("%w: invalid userset relation %q", ErrInvalidIdentifier, parts[1])
		}
		return SubjectTypeRule{
			Type:     parts[0],
			Relation: parts[1],
		}, nil
	}

	if !ValidateIdentifier(raw) {
		return SubjectTypeRule{}, fmt.Errorf("%w: invalid direct subject type %q", ErrInvalidIdentifier, raw)
	}

	return SubjectTypeRule{
		Type: raw,
	}, nil
}

// RawSchema is used for unmarshaling YAML schemas.
type RawSchema struct {
	Version int                   `yaml:"version" json:"version"`
	Types   map[string]RawTypeDef `yaml:"types" json:"types"`
}

// RawTypeDef is the YAML structure for a type definition.
type RawTypeDef struct {
	Relations   map[string][]string `yaml:"relations,omitempty" json:"relations,omitempty"`
	Permissions map[string]string   `yaml:"permissions,omitempty" json:"permissions,omitempty"`
}

// Schema represents a compiled, fully validated authz schema.
type Schema struct {
	Version int                        `json:"version"`
	Types   map[string]*TypeDefinition `json:"types"`
}

// TypeDefinition defines an object type, its relations, and its computed permissions.
type TypeDefinition struct {
	Name        string                           `json:"name"`
	Relations   map[string]*RelationDefinition   `json:"relations"`
	Permissions map[string]*PermissionDefinition `json:"permissions"`
}

// RelationDefinition defines a stored relation and allowed subject types.
type RelationDefinition struct {
	Name         string            `json:"name"`
	SubjectTypes []SubjectTypeRule `json:"subject_types"`
}

// PermissionDefinition defines a computed permission and its parsed AST.
type PermissionDefinition struct {
	Name       string `json:"name"`
	Expression string `json:"expression"`
	AST        Node   `json:"ast"`
}

// UnmarshalJSON implements custom JSON unmarshaling for AST nodes in PermissionDefinition.
func (p *PermissionDefinition) UnmarshalJSON(data []byte) error {
	var aux struct {
		Name       string          `json:"name"`
		Expression string          `json:"expression"`
		AST        json.RawMessage `json:"ast"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	p.Name = aux.Name
	p.Expression = aux.Expression
	if p.Expression != "" {
		ast, err := ParseExpression(p.Expression)
		if err != nil {
			return err
		}
		p.AST = ast
	}
	return nil
}

// ParseAndValidate compiles and validates a YAML schema string.
func ParseAndValidate(yamlContent string) (*Schema, error) {
	if strings.TrimSpace(yamlContent) == "" {
		return nil, errors.New("schema content is empty")
	}

	var raw RawSchema
	if err := yaml.Unmarshal([]byte(yamlContent), &raw); err != nil {
		return nil, fmt.Errorf("YAML syntax error: %w", err)
	}

	return ValidateRawSchema(&raw)
}
