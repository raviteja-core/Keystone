package schema_test

import (
	"testing"

	"github.com/raviteja-core/keystone/internal/authz/schema"
)

func FuzzExpressionParser(f *testing.F) {
	// Seed corpus
	seeds := []string{
		"owner",
		"owner + editor",
		"owner & editor",
		"owner - banned",
		"parent->edit",
		"(edit + viewer) - banned",
		"a + b & c - d",
		"((a + b) + c)",
		"(a + (b - c))",
		"owner + editor + parent->edit",
		"",
		"   ",
		"+++",
		"parent->",
		"(",
		")",
		"((()))",
		"a -> b",
		"a->b->c",
		"a + @invalid",
		"123abc",
		"a-b",
		"a - b",
		"a & (b + c)",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, expr string) {
		// Must not panic or hang
		_, _ = schema.ParseExpression(expr)
	})
}
