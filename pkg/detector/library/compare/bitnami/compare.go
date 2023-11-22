package bitnami

import (
	version "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Comparer represents a comparer for Bitnami
type Comparer struct{}

// IsVulnerable checks if the package version is vulnerable to the advisory.
func (n Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, n.matchVersion)
}

// matchVersion checks if the package version satisfies the given constraint.
func (n Comparer) matchVersion(currentVersion, constraint string) (bool, error) {
	v, err := version.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("bitnami version error (%s): %s", currentVersion, err)
	}

	cs, err := newConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("bitnami constraint error (%s): %s", constraint, err)
	}

	for _, c := range cs {
		if c.operator(v, c.version) {
			return true, nil
		}
	}

	return false, nil
}
