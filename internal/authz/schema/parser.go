package schema

import (
	"errors"
	"fmt"
	"unicode"
)

const (
	MaxExpressionLength = 2048
	MaxNestingDepth     = 32
	MaxNameLength       = 64
)

var (
	ErrEmptyExpression      = errors.New("permission expression cannot be empty")
	ErrExpressionTooLong    = errors.New("permission expression exceeds maximum length of 2048 characters")
	ErrNestingTooDeep       = errors.New("permission expression exceeds maximum nesting depth of 32")
	ErrInvalidIdentifier    = errors.New("invalid identifier")
	ErrUnexpectedToken      = errors.New("unexpected token in permission expression")
	ErrUnmatchedParenthesis = errors.New("unmatched parenthesis in permission expression")
)

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokIdent
	tokPlus
	tokAmpersand
	tokMinus
	tokArrow
	tokLParen
	tokRParen
)

type token struct {
	kind tokenKind
	val  string
	pos  int
}

type lexer struct {
	src []rune
	pos int
}

func newLexer(s string) *lexer {
	return &lexer{src: []rune(s), pos: 0}
}

func (l *lexer) nextToken() (token, error) {
	l.skipWhitespace()
	if l.pos >= len(l.src) {
		return token{kind: tokEOF, pos: l.pos}, nil
	}

	startPos := l.pos
	ch := l.src[l.pos]

	switch ch {
	case '+':
		l.pos++
		return token{kind: tokPlus, val: "+", pos: startPos}, nil
	case '&':
		l.pos++
		return token{kind: tokAmpersand, val: "&", pos: startPos}, nil
	case '-':
		if l.pos+1 < len(l.src) && l.src[l.pos+1] == '>' {
			l.pos += 2
			return token{kind: tokArrow, val: "->", pos: startPos}, nil
		}
		l.pos++
		return token{kind: tokMinus, val: "-", pos: startPos}, nil
	case '(':
		l.pos++
		return token{kind: tokLParen, val: "(", pos: startPos}, nil
	case ')':
		l.pos++
		return token{kind: tokRParen, val: ")", pos: startPos}, nil
	default:
		if ch >= 'a' && ch <= 'z' {
			return l.scanIdent(startPos)
		}
		return token{}, fmt.Errorf("%w at character %d: unexpected character %q", ErrUnexpectedToken, startPos, ch)
	}
}

func (l *lexer) skipWhitespace() {
	for l.pos < len(l.src) && unicode.IsSpace(l.src[l.pos]) {
		l.pos++
	}
}

func (l *lexer) scanIdent(startPos int) (token, error) {
	for l.pos < len(l.src) {
		ch := l.src[l.pos]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' {
			l.pos++
		} else {
			break
		}
	}

	val := string(l.src[startPos:l.pos])
	if len(val) > MaxNameLength {
		return token{}, fmt.Errorf("%w: identifier %q exceeds %d characters", ErrInvalidIdentifier, val, MaxNameLength)
	}
	return token{kind: tokIdent, val: val, pos: startPos}, nil
}

// Parser parses permission expressions into an AST.
type parser struct {
	tokens []token
	curr   int
	depth  int
}

// ParseExpression parses an expression string into an AST Node.
func ParseExpression(expr string) (Node, error) {
	if len(expr) == 0 {
		return nil, ErrEmptyExpression
	}
	if len(expr) > MaxExpressionLength {
		return nil, ErrExpressionTooLong
	}

	lex := newLexer(expr)
	var tokens []token
	for {
		tok, err := lex.nextToken()
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, tok)
		if tok.kind == tokEOF {
			break
		}
	}

	if len(tokens) == 1 && tokens[0].kind == tokEOF {
		return nil, ErrEmptyExpression
	}

	p := &parser{tokens: tokens, curr: 0, depth: 0}
	node, err := p.parseExpr()
	if err != nil {
		return nil, err
	}

	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("%w at character %d: unexpected token %q after expression", ErrUnexpectedToken, p.peek().pos, p.peek().val)
	}

	return node, nil
}

func (p *parser) peek() token {
	if p.curr < len(p.tokens) {
		return p.tokens[p.curr]
	}
	return token{kind: tokEOF}
}

func (p *parser) advance() token {
	t := p.peek()
	if p.curr < len(p.tokens) {
		p.curr++
	}
	return t
}

// expr := term (op term)*
func (p *parser) parseExpr() (Node, error) {
	left, err := p.parseTerm()
	if err != nil {
		return nil, err
	}

	for {
		tok := p.peek()
		var op NodeType
		switch tok.kind {
		case tokPlus:
			op = NodeUnion
		case tokAmpersand:
			op = NodeIntersection
		case tokMinus:
			op = NodeExclusion
		default:
			return left, nil
		}

		p.advance() // consume op

		right, err := p.parseTerm()
		if err != nil {
			return nil, err
		}

		left = &BinaryNode{
			Op:    op,
			Left:  left,
			Right: right,
		}
	}
}

// term := name | name '->' name | '(' expr ')'
func (p *parser) parseTerm() (Node, error) {
	tok := p.peek()

	switch tok.kind {
	case tokIdent:
		p.advance()
		if p.peek().kind == tokArrow {
			p.advance() // consume '->'
			permTok := p.peek()
			if permTok.kind != tokIdent {
				return nil, fmt.Errorf("%w at character %d: expected permission name after '->', got %q", ErrUnexpectedToken, permTok.pos, permTok.val)
			}
			p.advance()
			return &ArrowNode{
				Relation:   tok.val,
				Permission: permTok.val,
			}, nil
		}
		return &NameNode{Name: tok.val}, nil

	case tokLParen:
		p.advance() // consume '('
		p.depth++
		if p.depth > MaxNestingDepth {
			return nil, ErrNestingTooDeep
		}

		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}

		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("%w at character %d: expected ')'", ErrUnmatchedParenthesis, p.peek().pos)
		}
		p.advance() // consume ')'
		p.depth--
		return inner, nil

	default:
		return nil, fmt.Errorf("%w at character %d: expected term (identifier, arrow, or '('), got %q", ErrUnexpectedToken, tok.pos, tok.val)
	}
}
