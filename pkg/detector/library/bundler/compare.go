package bundler

import (
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/library/comparer"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-gem-version"
)

type RubyGemsComparer struct{}

func (r RubyGemsComparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return comparer.IsVulnerable(ver, advisory, r.MatchVersion)
}

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
