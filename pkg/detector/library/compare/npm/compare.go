package npm

import (
	"strings"

	"golang.org/x/xerrors"

	npm "github.com/aquasecurity/go-npm-version/pkg"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Comparer represents a comparer for npm
type Comparer struct{}

func normalizeVersion(ver string) string {
	if idx := strings.Index(ver, "-canary"); idx != -1 {
		return ver[:idx]
	}
	return ver
}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (n Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	normalizedVer := normalizeVersion(ver)
	return compare.IsVulnerable(normalizedVer, advisory, n.MatchVersion)
}

// MatchVersion checks if the package version satisfies the given constraint.
func (n Comparer) MatchVersion(currentVersion, constraint string) (bool, error) {
	v, err := npm.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("npm version error (%s): %s", currentVersion, err)
	}

	c, err := npm.NewConstraints(constraint, npm.WithPreRelease(true))
	if err != nil {
		return false, xerrors.Errorf("npm constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
