// Package composer checks Composer package versions against advisories with the version
// order of Composer.
//
// Composer does not follow SemVer: it gives a version up to four numbers and a stability,
// and it orders the stabilities as dev, alpha, beta, RC, the release and then patch. A
// patch such as "2.4.6-p1" therefore follows "2.4.6", where SemVer reads it as a
// pre-release that precedes it.
// https://getcomposer.org/doc/articles/versions.md
package composer

import (
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Comparer represents a comparer for Composer
type Comparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (c Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, c.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
//
// Some advisories name a version Composer cannot read, such as "<6.0.0-GM", and so may a
// package that was not installed by Composer. Those have no place in the version order of
// Composer, so they are compared as before, as SemVer-like versions.
func (c Comparer) matchVersion(currentVersion, constraint string) (bool, error) {
	v, err := parseVersion(currentVersion)
	if err != nil {
		return compare.GenericComparer{}.MatchVersion(currentVersion, constraint)
	}

	cs, err := parseConstraints(constraint)
	if err != nil {
		return compare.GenericComparer{}.MatchVersion(currentVersion, constraint)
	}

	return cs.check(v), nil
}

// constraintRegexp matches an operator, which may be left out, and the version it applies to.
var constraintRegexp = regexp.MustCompile(`^(==|=|!=|<>|>=|<=|>|<)?\s*([^\s,]+)`)

// constraint is a version with the operator a checked version is compared to it with.
type constraint struct {
	operator string
	version  version
}

// constraints is a list of alternatives. A version satisfies them if it satisfies every
// constraint of at least one alternative.
type constraints [][]constraint

// parseConstraints parses the ranges of an advisory, such as ">=2.4.6, <2.4.6-p4 || <2.4.4".
// Alternatives are separated by "||", and the constraints of an alternative by a comma or
// a space.
//
// The constraints are compared by the version order alone, as in the other ecosystems.
// Composer itself reads "<2.0.0" in a requirement as "<2.0.0-dev", which leaves out the
// pre-releases of 2.0.0. An advisory that names 2.0.0 as the fixed version does not mean
// that, since a pre-release of the fixed version may still be vulnerable.
func parseConstraints(s string) (constraints, error) {
	var cs constraints
	for alternative := range strings.SplitSeq(s, "||") {
		var group []constraint
		rest := strings.TrimSpace(alternative)
		for rest != "" {
			m := constraintRegexp.FindStringSubmatch(rest)
			if m == nil {
				return nil, xerrors.Errorf("improper constraint: %q", alternative)
			}

			v, err := parseVersion(m[2])
			if err != nil {
				return nil, err
			}
			group = append(group, constraint{
				operator: m[1],
				version:  v,
			})

			rest = strings.TrimLeft(rest[len(m[0]):], ", \t")
		}
		if len(group) == 0 {
			return nil, xerrors.Errorf("empty constraint: %q", s)
		}
		cs = append(cs, group)
	}
	return cs, nil
}

func (cs constraints) check(v version) bool {
	for _, group := range cs {
		satisfied := true
		for _, c := range group {
			if !c.check(v) {
				satisfied = false
				break
			}
		}
		if satisfied {
			return true
		}
	}
	return false
}

func (c constraint) check(v version) bool {
	result := v.compare(c.version)
	switch c.operator {
	case ">":
		return result > 0
	case ">=":
		return result >= 0
	case "<":
		return result < 0
	case "<=":
		return result <= 0
	case "!=", "<>":
		return result != 0
	default: // "", "=" and "=="
		return result == 0
	}
}
