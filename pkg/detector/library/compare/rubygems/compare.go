package rubygems

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-gem-version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Comparer represents a comparer for RubyGems
type Comparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (r Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, r.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
func (r Comparer) matchVersion(currentVersion, constraint string) (bool, error) {
	v, err := gem.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("RubyGems version error (%s): %s", currentVersion, err)
	}

	c, err := gem.NewConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("RubyGems constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
