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

func Normalize(license string, funcs ...NormalizeFunc) (Expression, error) {
	expr, err := parse(license)
	if err != nil {
		return nil, xerrors.Errorf("license (%s) parse error: %w", license, err)
	}
	for _, fn := range funcs {
		expr = normalize(expr, fn)
	}

	return expr, nil
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

// NormalizeForSPDX rewrites an expression to match the SPDX license expression syntax:
//   - in a license-id, characters outside the idstring set are replaced with '-'
//     (a license-id MUST NOT contain white space, while the "WITH" operator MUST be
//     surrounded by it);
//   - a license-id found in the SPDX license list is replaced with its canonical spelling;
//   - the exception-id of a "WITH" expression is replaced with its canonical spelling.
//
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
		license := b.String()
		// A license can differ from its SPDX ID by a non-canonical separator
		// (e.g. "BSD-3-clause~Sun") or by case. Separators are replaced above and
		// the SPDX list is matched case-insensitively, so take the canonical ID.
		if id, ok := SPDXLicenseID(license); ok {
			license = id
		}
		return SimpleExpr{License: license, HasPlus: e.HasPlus}
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
