package utils

import (
	"fmt"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	replacer = strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc")
)

func MatchVersions(currentVersion *semver.Version, rangeVersions []string) bool {
	for i := range rangeVersions {
		rangeVersions[i] = replacer.Replace(rangeVersions[i])
		constraintParts := strings.Split(rangeVersions[i], ",")
		for j := range constraintParts {
			part := strings.Split(constraintParts[j], ".")
			if len(part) > 3 {
				constraintParts[j] = strings.Join(part[:2], ".") + "." + strings.Join(part[2:], "-")
			}
		}
		rangeVersions[i] = strings.Join(constraintParts, ",")
		c, err := semver.NewConstraint(rangeVersions[i])
		if err != nil {
			log.Logger.Error("NewConstraint", "error", err)
			continue
		}
		// Validate a version against a constraint.
		valid, msgs := c.Validate(currentVersion)
		if valid {
			return true
		}
		for _, m := range msgs {
			// re-validate after removing the patch version
			if strings.HasSuffix(m.Error(), "is a prerelease version and the constraint is only looking for release versions") {
				if v2, err := semver.NewVersion(fmt.Sprintf("%v.%v.%v", currentVersion.Major(), currentVersion.Minor(), currentVersion.Patch())); err == nil {
					valid, msgs = c.Validate(v2)
					if valid {
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
