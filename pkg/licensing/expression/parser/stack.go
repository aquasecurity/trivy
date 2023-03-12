package parser

import (
	"github.com/aquasecurity/trivy/pkg/licensing/expression/token"
)

type Pair struct {
	root    *LicenseExpression
	cursor  *LicenseExpression
	bracket token.TokenType
}

type Stack []Pair

func (s *Stack) Push(x Pair) {
	*s = append(*s, x)
}

func (s *Stack) Pop() Pair {
	l := len(*s)
	x := (*s)[l-1]
	*s = (*s)[:l-1]
	return x
}

func (s *Stack) IsEmpty() bool {
	return len(*s) == 0
}
