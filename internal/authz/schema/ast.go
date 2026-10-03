package schema

import "fmt"

// NodeType identifies the type of an AST node in permission expressions.
type NodeType string

const (
	NodeUnion        NodeType = "union"
	NodeIntersection NodeType = "intersection"
	NodeExclusion    NodeType = "exclusion"
	NodeName         NodeType = "name"
	NodeArrow        NodeType = "arrow"
)

// Node represents an element in an expression AST.
type Node interface {
	Type() NodeType
	String() string
}

// NameNode represents a reference to a relation or another permission on the same object.
type NameNode struct {
	Name string `json:"name"`
}

func (n *NameNode) Type() NodeType { return NodeName }
func (n *NameNode) String() string { return n.Name }

// ArrowNode represents tuple-to-userset (rel->perm).
type ArrowNode struct {
	Relation   string `json:"relation"`
	Permission string `json:"permission"`
}

func (n *ArrowNode) Type() NodeType { return NodeArrow }
func (n *ArrowNode) String() string { return fmt.Sprintf("%s->%s", n.Relation, n.Permission) }

// BinaryNode represents a binary operation: union (+), intersection (&), or exclusion (-).
type BinaryNode struct {
	Op    NodeType `json:"op"`
	Left  Node     `json:"left"`
	Right Node     `json:"right"`
}

func (n *BinaryNode) Type() NodeType { return n.Op }
func (n *BinaryNode) String() string {
	var opSymbol string
	switch n.Op {
	case NodeUnion:
		opSymbol = "+"
	case NodeIntersection:
		opSymbol = "&"
	case NodeExclusion:
		opSymbol = "-"
	default:
		opSymbol = string(n.Op)
	}
	return fmt.Sprintf("(%s %s %s)", n.Left.String(), opSymbol, n.Right.String())
}
