package node

import (
	"golang.org/x/xerrors"

	npm "github.com/aquasecurity/go-npm-version/pkg"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"
)

type NpmComparer struct{}

func (n NpmComparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return comparer.IsVulnerable(ver, advisory, n.MatchVersion)
}

func (n NpmComparer) MatchVersion(currentVersion, constraint string) (bool, error) {
	v, err := npm.NewVersion(currentVersion)
	if err != nil {
		return false, xerrors.Errorf(" npm version error (%s): %s", currentVersion, err)
	}

	c, err := npm.NewConstraints(constraint)
	if err != nil {
		return false, xerrors.Errorf("npm constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}
