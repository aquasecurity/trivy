package expression

import (
	"fmt"

	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy/pkg/licensing"
)

var versioned = []string{
	licensing.AGPL10,
	licensing.AGPL30,
	licensing.GPL10,
	licensing.GPL20,
	licensing.GPL30,
	licensing.LGPL20,
	licensing.LGPL21,
	licensing.LGPL30,
}

type Expression interface {
	String() string
}

type Token struct {
	token   int
	literal string
}

type SimpleExpr struct {
	license string
	hasPlus bool
}

func (s SimpleExpr) String() string {
	if slices.Contains(versioned, s.license) {
		if s.hasPlus {
			// e.g. AGPL-1.0-or-later
			return s.license + "-or-later"
		}
		// e.g. GPL-1.0-only
		return s.license + "-only"
	}

	if s.hasPlus {
		return s.license + "+"
	}
	return s.license
}

type CompoundExpr struct {
	left        Expression
	conjunction Token
	right       Expression
}

func (c CompoundExpr) String() string {
	left := c.left.String()
	if _, ok := c.left.(CompoundExpr); ok {
		left = fmt.Sprintf("(%s)", left)
	}
	right := c.right.String()
	if _, ok := c.right.(CompoundExpr); ok {
		right = fmt.Sprintf("(%s)", right)
	}
	return fmt.Sprintf("%s %s %s", left, c.conjunction.literal, right)
}
