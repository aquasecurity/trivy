package generic

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/version"
)

// Comparer represents a comparer for semver-like versioning
type Comparer struct{}

// MatchVersion checks if the package version satisfies the given constraint.
func (v Comparer) MatchVersion(currentVersion, constraint string) (bool, error) {
	ver, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("constraint error (%s): %s", currentVersion, err)
	}

	return c.Check(ver), nil
}
