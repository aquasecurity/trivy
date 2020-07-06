package utils

import (
	"fmt"
	"strings"

	semver "github.com/Masterminds/semver"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/knqyf263/go-version"
)

var (
	replacer = strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc")
)

func MatchVersions(currentVersion *version.Version, rangeVersions []string) bool {
	v, err := semver.NewVersion(currentVersion.String())
	if err != nil {
		log.Logger.Error("NewVersion", "error", err)
		return false
	}
	for i := range rangeVersions {
		rangeVersions[i] = replacer.Replace(rangeVersions[i])
		c, err := semver.NewConstraint(rangeVersions[i])
		if err != nil {
			log.Logger.Error("NewConstraint", "error", err)
			continue
		}
		// Validate a version against a constraint.
		a, msgs := c.Validate(v)
		if a {
			return true
		}
		for _, m := range msgs {
			// re-validate after removing the patch version
			if strings.HasSuffix(m.Error(), "is a prerelease version and the constraint is only looking for release versions") {
				if v2, err := semver.NewVersion(fmt.Sprintf("%v.%v.%v", v.Major(), v.Minor(), v.Patch())); err == nil {
					a, msgs = c.Validate(v2)
					if a {
						return true
					}
				}
			}
		}
	}
	return false
}

func FormatVersion(pkg types.Package) string {
	return formatVersion(pkg.Epoch, pkg.Version, pkg.Release)
}

func FormatSrcVersion(pkg types.Package) string {
	return formatVersion(pkg.SrcEpoch, pkg.SrcVersion, pkg.SrcRelease)
}

func formatVersion(epoch int, version, release string) string {
	v := version
	if release != "" {
		v = fmt.Sprintf("%s-%s", v, release)
	}
	if epoch != 0 {
		v = fmt.Sprintf("%d:%s", epoch, v)
	}
	return v

}
