package maven

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
)

// MavenComparer represents a comparer for maven
type MavenComparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (n MavenComparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return comparer.IsVulnerable(ver, advisory, n.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
func (n MavenComparer) matchVersion(currentVersion, constraint string) (bool, error) {
	// TODO: use go-mvn-version
	v, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("maven version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("maven constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
