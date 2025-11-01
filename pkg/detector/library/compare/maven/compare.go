package maven

import (
	version "github.com/masahiro331/go-mvn-version"
	"golang.org/x/xerrors"
)

// Comparer represents a comparer for maven
type Comparer struct{}

// MatchVersion checks if the package version satisfies the given constraint.
func (n Comparer) MatchVersion(currentVersion, constraint string) (bool, error) {
	v, err := version.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("maven version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewComparer(constraint)
	if err != nil {
		return false, xerrors.Errorf("maven constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
