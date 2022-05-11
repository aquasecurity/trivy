package json

import (
	"github.com/hashicorp/hcl/v2"
)

// IsJSONExpression returns true if and only if the given expression is one
// that originated in a JSON document.
//
// Applications aiming to be syntax-agnostic should not use this function and
// should instead use the normal expression evaluation or static analysis
// APIs.
//
// However, JSON expressions do have a unique behavior whereby they interpret
// the source JSON differently depending on the hcl.EvalContext value passed
// to the Value method -- in particular, a nil hcl.EvalContext returns
// literal strings rather than interpreting them as HCL template syntax --
// and so in exceptional cases an application may wish to rely on that behavior
// in situations where it specifically knows the expression originated in JSON,
// in case it needs to do some non-standard handling of the expression in that
// case.
//
// Caution: The normal HCL API allows for HCL expression implementations that
// wrap other HCL expression implementations. This function will return false
// if given an expression of some other type that encapsulates a JSON
// expression, even if the wrapper implementation would in principle preserve
// the special evaluation behavior of the wrapped expression.
func IsJSONExpression(maybeJSONExpr hcl.Expression) bool {
	_, ok := maybeJSONExpr.(*expression)
	return ok
}

// IsJSONBody returns true if and only if the given body is one that originated
// in a JSON document.
//
// Applications aiming to be syntax-agnostic should not use this function and
// should instead use the normal schema-driven or "just attributes' decoding
// APIs.
//
// Howeer, JSON expressions do have a unique behavior whereby various different
// source JSON shapes can be interpreted in different ways depending on the
// given schema, and so in exceptional cases an application may need to
// perform some deeper analysis first in order to distinguish variants of
// different physical structure.
//
// Caution: The normal HCL API allows for HCL body implementations that wrap
// other HCL body implementations. This function will return false if given an
// expression of some other type that encapsulates a JSON body, even if
// the wrapper implementation would in principle preserve the special
// decoding behavior of the wrapped body.
func IsJSONBody(maybeJSONBody hcl.Body) bool {
	_, ok := maybeJSONBody.(*body)
	return ok
}
