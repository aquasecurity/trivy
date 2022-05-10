package npm

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/part"
	"github.com/aquasecurity/go-version/pkg/semver"
)

const cvRegex string = `v?([0-9|x|X|\*]+)(\.[0-9|x|X|\*]+)?(\.[0-9|x|X|\*]+)?` +
	`(-([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?` +
	`(\+([0-9A-Za-z\-]+(\.[0-9A-Za-z\-]+)*))?`

var (
	constraintOperators = map[string]operatorFunc{
		"":   constraintEqual,
		"=":  constraintEqual,
		"==": constraintEqual,
		">":  constraintGreaterThan,
		"<":  constraintLessThan,
		">=": constraintGreaterThanEqual,
		"=>": constraintGreaterThanEqual,
		"<=": constraintLessThanEqual,
		"=<": constraintLessThanEqual,
		"~":  constraintTilde,
		"^":  constraintCaret,
	}
	constraintRegexp      *regexp.Regexp
	validConstraintRegexp *regexp.Regexp
)

type operatorFunc func(v, c Version) bool

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

// Constraints is one or more constraint that a npm version can be
// checked against.
type Constraints [][]constraint

type constraint struct {
	version  Version
	operator operatorFunc
	original string
}

// NewConstraints parses the given string and returns an instance of Constraints
func NewConstraints(v string) (Constraints, error) {
	var css [][]constraint
	for _, vv := range strings.Split(v, "||") {
		// Validate the segment
		if !validConstraintRegexp.MatchString(vv) {
			return Constraints{}, xerrors.Errorf("improper constraint: %s", vv)
		}

		ss := constraintRegexp.FindAllString(vv, -1)
		if ss == nil {
			ss = append(ss, strings.TrimSpace(vv))
		}

		var cs []constraint
		for _, single := range ss {
			c, err := newConstraint(single)
			if err != nil {
				return Constraints{}, err
			}
			cs = append(cs, c)
		}
		css = append(css, cs)
	}

	return css, nil

}

func newConstraint(c string) (constraint, error) {
	if c == "" {
		return constraint{
			version: semver.New(part.Any(true), part.Any(true), part.Any(true),
				part.NewParts("*"), ""),
			operator: constraintOperators[""],
		}, nil
	}

	m := constraintRegexp.FindStringSubmatch(c)
	if m == nil {
		return constraint{}, xerrors.Errorf("improper constraint: %s", c)
	}

	major := m[3]
	minor := strings.TrimPrefix(m[4], ".")
	patch := strings.TrimPrefix(m[5], ".")
	pre := part.NewParts(strings.TrimPrefix(m[6], "-"))

	v := semver.New(newPart(major), newPart(minor), newPart(patch), pre, "")

	return constraint{
		version:  v,
		operator: constraintOperators[m[1]],
		original: c,
	}, nil
}

func newPart(p string) part.Part {
	if p == "" {
		p = "*"
	}
	return part.NewPart(p)
}

func (c constraint) check(v Version) bool {
	op := preCheck(c.operator)
	return op(v, c.version)
}

func (c constraint) String() string {
	return c.original
}

// Check tests if a version satisfies all the constraints.
func (cs Constraints) Check(v Version) bool {
	for _, c := range cs {
		if andCheck(v, c) {
			return true
		}
	}

	return false
}

// Returns the string format of the constraints
func (cs Constraints) String() string {
	var csStr []string
	for _, orC := range cs {
		var cstr []string
		for _, andC := range orC {
			cstr = append(cstr, andC.String())
		}
		csStr = append(csStr, strings.Join(cstr, ","))
	}

	return strings.Join(csStr, "||")
}

func andCheck(v Version, constraints []constraint) bool {
	for _, c := range constraints {
		if !c.check(v) {
			return false
		}
	}
	return true
}

//-------------------------------------------------------------------
// Constraint functions
//-------------------------------------------------------------------

func constraintEqual(v, c Version) bool {
	return v.Equal(c)
}

func constraintGreaterThan(v, c Version) bool {
	if c.IsPreRelease() && v.IsPreRelease() {
		return v.Release().Equal(c.Release()) && v.GreaterThan(c)
	}
	return v.GreaterThan(c)
}

func constraintLessThan(v, c Version) bool {
	if c.IsPreRelease() && v.IsPreRelease() {
		return v.Release().Equal(c.Release()) && v.LessThan(c)
	}
	return v.LessThan(c)
}

func constraintGreaterThanEqual(v, c Version) bool {
	if c.IsPreRelease() && v.IsPreRelease() {
		return v.Release().Equal(c.Release()) && v.GreaterThanOrEqual(c)
	}
	return v.GreaterThanOrEqual(c)
}

func constraintLessThanEqual(v, c Version) bool {
	if c.IsPreRelease() && v.IsPreRelease() {
		return v.Release().Equal(c.Release()) && v.LessThanOrEqual(c)
	}
	return v.LessThanOrEqual(c)
}

func constraintTilde(v, c Version) bool {
	// ~*, ~>* --> >= 0.0.0 (any)
	// ~2, ~2.x, ~2.x.x, ~>2, ~>2.x ~>2.x.x --> >=2.0.0, <3.0.0
	// ~2.0, ~2.0.x, ~>2.0, ~>2.0.x --> >=2.0.0, <2.1.0
	// ~1.2, ~1.2.x, ~>1.2, ~>1.2.x --> >=1.2.0, <1.3.0
	// ~1.2.3, ~>1.2.3 --> >=1.2.3, <1.3.0
	// ~1.2.0, ~>1.2.0 --> >=1.2.0, <1.3.0
	if c.IsPreRelease() && v.IsPreRelease() {
		return v.GreaterThanOrEqual(c) && v.LessThan(c.Release())
	}
	return v.GreaterThanOrEqual(c) && v.LessThan(c.TildeBump())
}

func constraintCaret(v, c Version) bool {
	// ^*      -->  (any)
	// ^1.2.3  -->  >=1.2.3 <2.0.0
	// ^1.2    -->  >=1.2.0 <2.0.0
	// ^1      -->  >=1.0.0 <2.0.0
	// ^0.2.3  -->  >=0.2.3 <0.3.0
	// ^0.2    -->  >=0.2.0 <0.3.0
	// ^0.0.3  -->  >=0.0.3 <0.0.4
	// ^0.0    -->  >=0.0.0 <0.1.0
	// ^0      -->  >=0.0.0 <1.0.0
	if c.IsPreRelease() && v.IsPreRelease() {
		return v.GreaterThanOrEqual(c) && v.LessThan(c.Release())
	}
	return v.GreaterThanOrEqual(c) && v.LessThan(c.CaretBump())
}

func preCheck(f operatorFunc) operatorFunc {
	return func(v, c Version) bool {
		if v.IsPreRelease() && !c.IsPreRelease() {
			return false
		} else if c.IsPreRelease() && c.IsAny() {
			return false
		}
		return f(v, c)
	}
}
