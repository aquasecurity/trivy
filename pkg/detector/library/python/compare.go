package python

import (
	"golang.org/x/xerrors"

	version "github.com/aquasecurity/go-pep440-version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
)

// Pep440Comparer represents a comparer for PEP 440
type Pep440Comparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (n Pep440Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return comparer.IsVulnerable(ver, advisory, n.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
func (n Pep440Comparer) matchVersion(currentVersion, constraint string) (bool, error) {
	v, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("python version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewSpecifiers(constraint, version.WithPreRelease(true))
	if err != nil {
		return false, xerrors.Errorf("python constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
