// Package node compares Node.js runtime versions against Node.js core advisories.
package node

import (
	"golang.org/x/xerrors"

	npmversion "github.com/aquasecurity/go-npm-version/pkg"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare"
)

// Comparer compares Node.js runtime versions.
type Comparer struct{}

// IsVulnerable checks if the runtime version is vulnerable to the advisory.
func (c Comparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return compare.IsVulnerable(ver, advisory, c.MatchVersion)
}

// MatchVersion checks whether a Node.js version satisfies the advisory constraint.
func (Comparer) MatchVersion(currentVersion, constraint string) (bool, error) {
	v, err := npmversion.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("Node.js version error (%s): %s", currentVersion, err)
	}
	c, err := npmversion.NewConstraints(constraint, npmversion.WithPreRelease(true))
	if err != nil {
		return false, xerrors.Errorf("Node.js constraint error (%s): %s", constraint, err)
	}
	return c.Check(v), nil
}
