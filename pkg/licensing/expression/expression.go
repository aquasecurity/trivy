package expression

import (
	"strings"
	"unicode"

	"golang.org/x/xerrors"
)

var (
	ErrInvalidExpression = xerrors.New("invalid expression error")
)

type NormalizeFunc func(license Expression) Expression

func parse(license string) (Expression, error) {
	l := NewLexer(strings.NewReader(license))
	if yyParse(l) != 0 {
		return nil, xerrors.Errorf("license parse error: %w", l.Err())
	} else if err := l.Err(); err != nil {
		return nil, err
	}

	return l.result, nil
}

func Normalize(license string, funcs ...NormalizeFunc) (string, error) {
	expr, err := parse(license)
	if err != nil {
		return "", xerrors.Errorf("license (%s) parse error: %w", license, err)
	}
	for _, fn := range funcs {
		expr = normalize(expr, fn)
	}

	return expr.String(), nil
}

func normalize(expr Expression, fn NormalizeFunc) Expression {
	// Apply normalization function first
	normalized := fn(expr)

	switch e := normalized.(type) {
	case SimpleExpr:
		// No further normalization for SimpleExpr
	case CompoundExpr:
		// Only recursively process if the result is a CompoundExpr
		e.left = normalize(e.left, fn)
		e.right = normalize(e.right, fn)
		e.conjunction.literal = strings.ToUpper(e.conjunction.literal) // e.g. "and" => "AND"
		return e
	}

	return normalized
}

// NormalizeForSPDX replaces ' ' to '-' in license-id.
// SPDX license MUST NOT have white space between a license-id.
// There MUST be white space on either side of the operator "WITH".
// ref: https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions
func NormalizeForSPDX(expr Expression) Expression {
	switch e := expr.(type) {
	case SimpleExpr:
		var b strings.Builder
		for _, c := range e.License {
			switch {
			// spec: idstring = 1*(ALPHA / DIGIT / "-" / "." )
			case isAlphabet(c) || unicode.IsNumber(c) || c == '-' || c == '.':
				_, _ = b.WriteRune(c)
			case c == ':':
				// TODO: Support DocumentRef
				_, _ = b.WriteRune(c)
			default:
				// Replace invalid characters with '-'
				_, _ = b.WriteRune('-')
			}
		}
		return SimpleExpr{License: b.String(), HasPlus: e.HasPlus}
	case CompoundExpr:
		if e.Conjunction() == TokenWith {
			initSpdxExceptions()
			// Use correct SPDX exceptionID
			if exc, ok := spdxExceptions[strings.ToUpper(e.Right().String())]; ok {
				return NewCompoundExpr(e.Left(), e.Conjunction(), exc)
			}
		}
	}
	return expr
}

func isAlphabet(r rune) bool {
	if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
		return false
	}
	return true
}
