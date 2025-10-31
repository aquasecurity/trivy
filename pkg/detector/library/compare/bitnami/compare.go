package bitnami

import (
	"github.com/bitnami/go-version/pkg/version"
	"golang.org/x/xerrors"
)

// Comparer represents a comparer for Bitnami
type Comparer struct{}

// MatchVersion checks if the package version satisfies the given constraint.
func (n Comparer) MatchVersion(currentVersion, constraint string) (bool, error) {
	v, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("bitnami version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("bitnami constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
