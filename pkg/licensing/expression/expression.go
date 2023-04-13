package expression

import (
	"strings"
	"unicode"

	"golang.org/x/xerrors"
)

var (
	ErrInvalidExpression = xerrors.New("invalid expression error")
)

type NormalizeFunc func(license string) string

func parse(license string) (Expression, error) {
	l := NewLexer(strings.NewReader(license))
	if yyParse(l) != 0 {
		return nil, xerrors.Errorf("license parse error: %w", l.Err())
	} else if err := l.Err(); err != nil {
		return nil, err
	}

	return l.result, nil
}

func Normalize(license string, fn ...NormalizeFunc) (string, error) {
	expr, err := parse(license)
	if err != nil {
		return "", xerrors.Errorf("license (%s) parse error: %w", license, err)
	}
	expr = normalize(expr, fn...)

	return expr.String(), nil
}

func normalize(expr Expression, fn ...NormalizeFunc) Expression {
	switch e := expr.(type) {
	case SimpleExpr:
		for _, f := range fn {
			e.license = f(e.license)
		}
		return e
	case CompoundExpr:
		e.left = normalize(e.left, fn...)
		e.right = normalize(e.right, fn...)
		e.conjunction.literal = strings.ToUpper(e.conjunction.literal) // e.g. "and" => "AND"
		return e
	}

	return expr
}

// NormalizeForSPDX replaces ' ' to '-' in license-id.
// SPDX license MUST NOT be white space between a license-id.
// There MUST be white space on either side of the operator "WITH".
// ref: https://spdx.github.io/spdx-spec/v2.3/SPDX-license-expressions
func NormalizeForSPDX(s string) string {
	var b strings.Builder
	for _, c := range s {
		// idstring = 1*(ALPHA / DIGIT / "-" / "." )
		if isAlphabet(c) || unicode.IsNumber(c) || c == '-' || c == '.' {
			_, _ = b.WriteRune(c)
		} else if c == ':' {
			// TODO: Support DocumentRef
			_, _ = b.WriteRune(c)
		} else {
			// Replace invalid characters with '-'
			_, _ = b.WriteRune('-')
		}
	}
	return b.String()
}

func isAlphabet(r rune) bool {
	if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
		return false
	}
	return true
}
