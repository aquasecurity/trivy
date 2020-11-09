package bundler

import (
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-gem-version"
)

// RubyGemsComparer represents a comparer for RubyGems
type RubyGemsComparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (r RubyGemsComparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return comparer.IsVulnerable(ver, advisory, r.MatchVersion)
}

// MatchVersion checks if the package version satisfies the given constraint.
func (r RubyGemsComparer) MatchVersion(currentVersion, constraint string) (bool, error) {
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
