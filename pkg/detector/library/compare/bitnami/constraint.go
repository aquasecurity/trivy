// Inspired by https://github.com/aquasecurity/go-version/blob/main/pkg/semver/constraint.go
// It makes "constraints" compatible with go-deb-version available comparing functions.
package bitnami

import (
	"fmt"
	"regexp"
	"strings"

	version "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"
)

type operatorFunc func(v, v2 version.Version) bool

const cvRegex string = `v?([0-9|x|X|\*]+)(\.[0-9|x|X|\*]+)?(\.[0-9|x|X|\*]+)?` +
	`(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?` +
	`(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?`

var (
	constraintOperators = map[string]operatorFunc{
		"":   func(v, v2 version.Version) bool { return v.Equal(v2) },
		"=":  func(v, v2 version.Version) bool { return v.Equal(v2) },
		"==": func(v, v2 version.Version) bool { return v.Equal(v2) },
		"!=": func(v, v2 version.Version) bool { return !v.Equal(v2) },
		">":  func(v, v2 version.Version) bool { return v.GreaterThan(v2) },
		"<":  func(v, v2 version.Version) bool { return v.LessThan(v2) },
		">=": func(v, v2 version.Version) bool { return v.Equal(v2) || v.GreaterThan(v2) },
		"=>": func(v, v2 version.Version) bool { return v.Equal(v2) || v.GreaterThan(v2) },
		"<=": func(v, v2 version.Version) bool { return v.Equal(v2) || v.LessThan(v2) },
		"=<": func(v, v2 version.Version) bool { return v.Equal(v2) || v.LessThan(v2) },
		// Caveats: "^" & "~" are not supported
	}
	constraintRegexp      *regexp.Regexp
	validConstraintRegexp *regexp.Regexp
)

func init() {
	ops := make([]string, 0, len(constraintOperators))
	for k := range constraintOperators {
		ops = append(ops, regexp.QuoteMeta(k))
	}

	constraintRegexp = regexp.MustCompile(fmt.Sprintf(
		`(%s)\s*(%s)`,
		strings.Join(ops, "|"),
		cvRegex))

	validConstraintRegexp = regexp.MustCompile(fmt.Sprintf(
		`^\s*(\s*(%s)\s*(%s)\s*\,?)*\s*$`,
		strings.Join(ops, "|"),
		cvRegex))
}

type constraint struct {
	version  version.Version
	operator operatorFunc
}

// newConstraints parses a given constraint and returns a slice of constraints.
func newConstraints(v string) ([]constraint, error) {
	var css []constraint
	for _, vv := range strings.Split(v, "||") {
		if !validConstraintRegexp.MatchString(vv) {
			return nil, xerrors.Errorf("improper constraint: %s", vv)
		}

		ss := constraintRegexp.FindAllString(vv, -1)
		if ss == nil {
			ss = append(ss, strings.TrimSpace(vv))
		}

		for _, single := range ss {
			m := constraintRegexp.FindStringSubmatch(single)
			if m == nil {
				return nil, xerrors.Errorf("improper constraint: %s", single)
			}

			v, err := version.NewVersion(m[2])
			if err != nil {
				return nil, xerrors.Errorf("invalid version: %s", m[2])
			}

			op, ok := constraintOperators[m[1]]
			if !ok {
				return nil, xerrors.Errorf("operator not found: %s", m[1])
			}

			css = append(css, constraint{
				version:  v,
				operator: op,
			})
		}
	}

	return css, nil
}
