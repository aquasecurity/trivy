package npm

import (
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	npm "github.com/aquasecurity/go-npm-version/pkg"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Comparer represents a comparer for npm
type Comparer struct{}

// normalizeConstraintString splits a constraint string that has multiple OR ranges
// separated by spaces into properly formatted ranges joined with " || ".
//
// Expected format from trivy-db: ">=X, <Y >=Z, <W ..."
// - Comma (,) = AND within a range
// - Space (between complete ranges) = OR between ranges
//
// The go-npm-version library expects OR groups to be separated by "||", not spaces.
// Example: ">=1.0.0, <2.0.0 >=2.0.0, <3.0.0" -> ">=1.0.0, <2.0.0 || >=2.0.0, <3.0.0"
func normalizeConstraintString(constraint string) string {
	if strings.Contains(constraint, "||") {
		return constraint
	}

	operatorPattern := regexp.MustCompile(`^\s*(>=|<=|>|<|==|!=|=|~|\^)`)
	var ranges []string
	var currentRange strings.Builder
	parts := strings.Fields(constraint)

	for i, part := range parts {
		if currentRange.Len() > 0 {
			currentRange.WriteString(" ")
		}
		currentRange.WriteString(part)

		if !strings.HasSuffix(part, ",") && i < len(parts)-1 {
			nextIsNewConstraint := operatorPattern.MatchString(parts[i+1])
			if nextIsNewConstraint {
				ranges = append(ranges, strings.TrimSpace(currentRange.String()))
				currentRange.Reset()
			}
		}
	}

	if currentRange.Len() > 0 {
		ranges = append(ranges, strings.TrimSpace(currentRange.String()))
	}

	if len(ranges) <= 1 {
		return constraint
	}

	return strings.Join(ranges, " || ")
}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (n Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, n.MatchVersion)
}

// MatchVersion checks if the package version satisfies the given constraint.
func (n Comparer) MatchVersion(currentVersion, constraint string) (bool, error) {
	v, err := npm.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("npm version error (%s): %s", currentVersion, err)
	}

	normalizedConstraint := normalizeConstraintString(constraint)

	c, err := npm.NewConstraints(normalizedConstraint, npm.WithPreRelease(true))
	if err != nil {
		return false, xerrors.Errorf("npm constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
