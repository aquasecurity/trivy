package comparer

import (
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/version"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// Comparer is an interface for version comparison
type Comparer interface {
	IsVulnerable(currentVersion string, advisory dbTypes.Advisory) bool
	MatchVersion(currentVersion, constraint string) (bool, error)
}

type matchVersion func(currentVersion, constraint string) (bool, error)

func IsVulnerable(pkgVer string, advisory dbTypes.Advisory, match matchVersion) bool {
	if len(advisory.VulnerableVersions) != 0 {
		matched, err := match(pkgVer, strings.Join(advisory.VulnerableVersions, " || "))
		if err != nil {
			log.Logger.Warn(err)
			return false
		}
		return matched
	}

	secureVersions := append(advisory.PatchedVersions, advisory.UnaffectedVersions...)
	matched, err := match(pkgVer, strings.Join(secureVersions, " || "))
	if err != nil {
		log.Logger.Warn(err)
		return false
	}
	return !matched
}

type GenericComparer struct{}

func (v GenericComparer) IsVulnerable(ver string, advisory dbTypes.Advisory) bool {
	return IsVulnerable(ver, advisory, v.MatchVersion)
}

func (v GenericComparer) MatchVersion(currentVersion, constraint string) (bool, error) {
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
