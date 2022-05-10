package rego

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
)

// ResultSet represents a collection of output from Rego evaluation. An empty
// result set represents an undefined query.
type ResultSet []Result

// Vars represents a collection of variable bindings. The keys are the variable
// names and the values are the binding values.
type Vars map[string]interface{}

// WithoutWildcards returns a copy of v with wildcard variables removed.
func (v Vars) WithoutWildcards() Vars {
	n := Vars{}
	for k, v := range v {
		if ast.Var(k).IsWildcard() || ast.Var(k).IsGenerated() {
			continue
		}
		n[k] = v
	}
	return n
}

// Result defines the output of Rego evaluation.
type Result struct {
	Expressions []*ExpressionValue `json:"expressions"`
	Bindings    Vars               `json:"bindings,omitempty"`
}

func newResult() Result {
	return Result{
		Bindings: Vars{},
	}
}

// Location defines a position in a Rego query or module.
type Location struct {
	Row int `json:"row"`
	Col int `json:"col"`
}

// ExpressionValue defines the value of an expression in a Rego query.
type ExpressionValue struct {
	Value    interface{} `json:"value"`
	Text     string      `json:"text"`
	Location *Location   `json:"location"`
}

func newExpressionValue(expr *ast.Expr, value interface{}) *ExpressionValue {
	result := &ExpressionValue{
		Value: value,
	}
	if expr.Location != nil {
		result.Text = string(expr.Location.Text)
		result.Location = &Location{
			Row: expr.Location.Row,
			Col: expr.Location.Col,
		}
	}
	return result
}

func (ev *ExpressionValue) String() string {
	return fmt.Sprint(ev.Value)
}

// Allowed is a helper method that'll return true if all of these conditions hold:
// - the result set only has one element
// - there is only one expression in the result set's only element
// - that expression has the value `true`
// - there are no bindings.
//
// If bindings are present, this will yield `false`: it would be a pitfall to
// return `true` for a query like `data.authz.allow = x`, which always has result
// set element with value true, but could also have a binding `x: false`.
func (rs ResultSet) Allowed() bool {
	if len(rs) == 1 && len(rs[0].Bindings) == 0 {
		if exprs := rs[0].Expressions; len(exprs) == 1 {
			if b, ok := exprs[0].Value.(bool); ok {
				return b
			}
		}
	}
	return false
}
