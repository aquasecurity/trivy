package rubygems

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-gem-version"
)

// Comparer represents a comparer for RubyGems
type Comparer struct{}

// MatchVersion checks if the package version satisfies the given constraint.
func (r Comparer) MatchVersion(currentVersion, constraint string) (bool, error) {
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
