package schema_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/raviteja-core/keystone/internal/authz/schema"
)

const validReferenceSchema = `
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
      verified_member: [user]
    permissions:
      edit:   "owner + editor + parent->edit"
      view:   "(edit + viewer + parent->view) - banned"
      delete: "owner"
      share:  "owner & verified_member"
`

func TestSchema_ValidReferenceSchema(t *testing.T) {
	s, err := schema.ParseAndValidate(validReferenceSchema)
	if err != nil {
		t.Fatalf("expected valid reference schema to compile, got error: %v", err)
	}

	if s.Version != 1 {
		t.Errorf("expected version 1, got %d", s.Version)
	}
	if len(s.Types) != 4 {
		t.Errorf("expected 4 types, got %d", len(s.Types))
	}

	docType, ok := s.Types["doc"]
	if !ok {
		t.Fatal("expected doc type to exist")
	}
	if len(docType.Relations) != 6 {
		t.Errorf("expected 6 relations on doc, got %d", len(docType.Relations))
	}
	if len(docType.Permissions) != 4 {
		t.Errorf("expected 4 permissions on doc, got %d", len(docType.Permissions))
	}

	// Verify view AST
	viewPerm, ok := docType.Permissions["view"]
	if !ok {
		t.Fatal("expected view permission on doc")
	}
	if viewPerm.AST.Type() != schema.NodeExclusion {
		t.Errorf("expected top-level node for view to be exclusion (-), got %s", viewPerm.AST.Type())
	}
}

func TestParser_LeftAssociativityAndPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected string
	}{
		{
			name:     "single name",
			expr:     "viewer",
			expected: "viewer",
		},
		{
			name:     "single arrow",
			expr:     "parent->edit",
			expected: "parent->edit",
		},
		{
			name:     "union left associative",
			expr:     "a + b + c",
			expected: "((a + b) + c)",
		},
		{
			name:     "mixed operators evaluated left to right",
			expr:     "a + b & c - d",
			expected: "(((a + b) & c) - d)",
		},
		{
			name:     "parentheses grouping",
			expr:     "(a + b) - c",
			expected: "((a + b) - c)",
		},
		{
			name:     "parentheses on right side",
			expr:     "a + (b - c)",
			expected: "(a + (b - c))",
		},
		{
			name:     "nested parentheses with arrow",
			expr:     "(edit + viewer + parent->view) - banned",
			expected: "(((edit + viewer) + parent->view) - banned)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, err := schema.ParseExpression(tt.expr)
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if ast.String() != tt.expected {
				t.Errorf("expected AST string %q, got %q", tt.expected, ast.String())
			}
		})
	}
}

func TestParser_SyntaxErrors(t *testing.T) {
	tests := []struct {
		name        string
		expr        string
		errContains string
	}{
		{"empty expression", "", "cannot be empty"},
		{"whitespace only", "   ", "cannot be empty"},
		{"invalid character @", "owner + @user", "unexpected character '@'"},
		{"invalid character $", "owner $ editor", "unexpected character '$'"},
		{"trailing plus", "owner +", "expected term"},
		{"double plus", "owner + + editor", "expected term"},
		{"missing closing paren", "(owner + editor", "expected ')'"},
		{"missing opening paren", "owner + editor)", "unexpected token \")\" after expression"},
		{"arrow missing permission", "parent->", "expected permission name after '->'"},
		{"arrow with non-ident right", "parent->(edit)", "expected permission name after '->'"},
		{"uppercase identifier", "Owner + editor", "unexpected character 'O'"},
		{"digit start identifier", "1owner + editor", "unexpected character '1'"},
		{"identifier too long", strings.Repeat("a", 65), "exceeds 64 characters"},
		{"expression too long", strings.Repeat("a + ", 600) + "a", "exceeds maximum length"},
		{"nesting too deep", strings.Repeat("(", 35) + "a" + strings.Repeat(")", 35), "exceeds maximum nesting depth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := schema.ParseExpression(tt.expr)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tt.expr)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
			}
		})
	}
}

func TestSchema_ValidationErrors(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		expectedErr error
		errContains string
	}{
		{
			name: "unsupported version",
			yaml: `
version: 2
types:
  user: {}
`,
			expectedErr: schema.ErrUnsupportedVersion,
		},
		{
			name: "no types defined",
			yaml: `
version: 1
types: {}
`,
			expectedErr: schema.ErrNoTypes,
		},
		{
			name: "invalid type name",
			yaml: `
version: 1
types:
  User: {}
`,
			expectedErr: schema.ErrInvalidIdentifier,
		},
		{
			name: "invalid relation name",
			yaml: `
version: 1
types:
  doc:
    relations:
      MyRelation: [doc]
`,
			expectedErr: schema.ErrInvalidIdentifier,
		},
		{
			name: "invalid permission name",
			yaml: `
version: 1
types:
  doc:
    relations:
      owner: [doc]
    permissions:
      CanView: "owner"
`,
			expectedErr: schema.ErrInvalidIdentifier,
		},
		{
			name: "name collision between relation and permission",
			yaml: `
version: 1
types:
  doc:
    relations:
      view: [doc]
    permissions:
      view: "view"
`,
			expectedErr: schema.ErrNameCollision,
		},
		{
			name: "unknown target type in relation rule",
			yaml: `
version: 1
types:
  doc:
    relations:
      owner: [nonexistent_type]
`,
			expectedErr: schema.ErrUnknownType,
		},
		{
			name: "unknown relation in userset subject type rule",
			yaml: `
version: 1
types:
  group: {}
  doc:
    relations:
      member: ["group#nonexistent_rel"]
`,
			expectedErr: schema.ErrUnknownRelation,
		},
		{
			name: "unknown name in permission expression",
			yaml: `
version: 1
types:
  doc:
    relations:
      owner: [doc]
    permissions:
      view: "owner + unknown_name"
`,
			expectedErr: schema.ErrUnknownPermission,
		},
		{
			name: "arrow left side is a permission instead of relation",
			yaml: `
version: 1
types:
  folder:
    permissions:
      edit: "edit"
  doc:
    relations:
      owner: [doc]
    permissions:
      parent_edit: "owner"
      view: "parent_edit->edit"
`,
			expectedErr: schema.ErrInvalidArrow,
		},
		{
			name: "arrow left side relation allows wildcard",
			yaml: `
version: 1
types:
  folder:
    permissions:
      view: "view"
  doc:
    relations:
      parent: [folder, "folder:*"]
    permissions:
      view: "parent->view"
`,
			expectedErr: schema.ErrInvalidArrow,
			errContains: "allows wildcard",
		},
		{
			name: "arrow left side relation allows userset",
			yaml: `
version: 1
types:
  folder:
    relations:
      member: [folder]
    permissions:
      view: "member"
  doc:
    relations:
      parent: [folder, "folder#member"]
    permissions:
      view: "parent->view"
`,
			expectedErr: schema.ErrInvalidArrow,
			errContains: "allows userset",
		},
		{
			name: "arrow target permission does not exist on target type",
			yaml: `
version: 1
types:
  folder: {}
  doc:
    relations:
      parent: [folder]
    permissions:
      view: "parent->nonexistent_perm"
`,
			expectedErr: schema.ErrUnknownPermission,
		},
		{
			name: "permission self cycle",
			yaml: `
version: 1
types:
  doc:
    permissions:
      view: "view"
`,
			expectedErr: schema.ErrPermissionCycle,
			errContains: "view -> view",
		},
		{
			name: "permission mutual cycle",
			yaml: `
version: 1
types:
  doc:
    relations:
      owner: [doc]
    permissions:
      edit: "owner + view"
      view: "edit"
`,
			expectedErr: schema.ErrPermissionCycle,
			errContains: "edit -> view -> edit",
		},
		{
			name: "permission 3-way cycle",
			yaml: `
version: 1
types:
  doc:
    relations:
      owner: [doc]
    permissions:
      a: "owner + b"
      b: "c"
      c: "a"
`,
			expectedErr: schema.ErrPermissionCycle,
			errContains: "a -> b -> c -> a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := schema.ParseAndValidate(tt.yaml)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if tt.expectedErr != nil && !errors.Is(err, tt.expectedErr) {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}
			if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error containing %q, got %q", tt.errContains, err.Error())
			}
		})
	}
}

func TestSchema_MaxTypesLimit(t *testing.T) {
	var b strings.Builder
	b.WriteString("version: 1\ntypes:\n")
	for i := 0; i < 65; i++ {
		name := fmt.Sprintf("type_%02d", i)
		b.WriteString("  " + name + ": {}\n")
	}

	_, err := schema.ParseAndValidate(b.String())
	if !errors.Is(err, schema.ErrTooManyTypes) {
		t.Fatalf("expected ErrTooManyTypes, got %v", err)
	}
}

func TestSchema_ValidDiamondGraphPerms(t *testing.T) {
	// a -> b, a -> c, b -> d, c -> d
	diamond := `
version: 1
types:
  doc:
    relations:
      owner: [doc]
    permissions:
      d: "owner"
      b: "d"
      c: "d"
      a: "b + c"
`
	s, err := schema.ParseAndValidate(diamond)
	if err != nil {
		t.Fatalf("diamond DAG should be valid, got: %v", err)
	}
	if len(s.Types["doc"].Permissions) != 4 {
		t.Errorf("expected 4 permissions, got %d", len(s.Types["doc"].Permissions))
	}
}
