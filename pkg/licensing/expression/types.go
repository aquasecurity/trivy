package expression

import (
	"fmt"
	"slices"
)

type Expression interface {
	String() string
}

type Token struct {
	token   int
	literal string
}

type SimpleExpr struct {
	License string
	HasPlus bool
}

func (s SimpleExpr) String() string {
	if slices.Contains(GnuLicenses, s.License) {
		if s.HasPlus {
			// e.g. AGPL-1.0-or-later
			return s.License + "-or-later"
		}
		// e.g. GPL-1.0-only
		return s.License + "-only"
	}

	if s.HasPlus {
		return s.License + "+"
	}
	return s.License
}

type CompoundExpr struct {
	left        Expression
	conjunction Token
	right       Expression
}

func (c CompoundExpr) String() string {
	left := c.left.String()
	if l, ok := c.left.(CompoundExpr); ok {
		// e.g. (A OR B) AND C
		if c.conjunction.token > l.conjunction.token {
			left = fmt.Sprintf("(%s)", left)
		}
	}
	right := c.right.String()
	if r, ok := c.right.(CompoundExpr); ok {
		// e.g. A AND (B OR C)
		if c.conjunction.token > r.conjunction.token {
			right = fmt.Sprintf("(%s)", right)
		}
	}
	return fmt.Sprintf("%s %s %s", left, c.conjunction.literal, right)
}
