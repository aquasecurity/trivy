package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"

	"github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	replacer           = strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc", "==", "=")
	preReleaseSplitter = regexp.MustCompile(`(?P<Number>^[0-9]+)(?P<PreRelease>[a-z]*.*)`)
)

// MatchVersions runs comparison on currentVersion based on rangeVersions and return true/false
func MatchVersions(currentVersion *semver.Version, rangeVersions []string) bool {
	for _, v := range rangeVersions {
		v = replacer.Replace(v)
		constraintParts := strings.Split(v, ",")
		for j := range constraintParts {
			constraintParts[j] = FormatPatchVersion(constraintParts[j])
		}
		v = strings.Join(constraintParts, ",")
		if v == "" {
			continue
		}
		c, err := semver.NewConstraint(v)
		if err != nil {
			log.Logger.Debug("NewConstraint", "error", err)
			continue
		}
		// Validate a version against a constraint.
		valid, msgs := c.Validate(currentVersion)
		if valid {
			return true
		}

		// In this case, it can either be a patch version or a revision version (c.Metadata()) or just a general error.
		if currentVersion.Metadata() != "" {
			valid, err := matchRevisionVersion(currentVersion, v)
			if err != nil {
				log.Logger.Debug("MatchRevision", "error", err)
				continue
			}
			if valid {
				return true
			}
		}

		for _, m := range msgs {
			// re-validate after removing the patch version
			if strings.HasSuffix(m.Error(), "is a prerelease version and the constraint is only looking for release versions") {
				v2, err := semver.NewVersion(fmt.Sprintf("%v.%v.%v", currentVersion.Major(), currentVersion.Minor(), currentVersion.Patch()))
				if err == nil {
					valid, _ = c.Validate(v2)
					if valid {
						return true
					}
				}
			}
		}
	}
	return false
}

// FormatVersion formats the package version based on epoch, version & release
func FormatVersion(pkg types.Package) string {
	return formatVersion(pkg.Epoch, pkg.Version, pkg.Release)
}

// FormatSrcVersion formats the package version based on source epoch, version & release
func FormatSrcVersion(pkg types.Package) string {
	return formatVersion(pkg.SrcEpoch, pkg.SrcVersion, pkg.SrcRelease)
}

// FormatPatchVersion returns the semver compatible version string given non-semver version
func FormatPatchVersion(version string) string {
	part := strings.Split(version, ".")
	if len(part) > 3 {
		if _, err := strconv.Atoi(part[2]); err == nil {
			version = strings.Join(part[:3], ".") + "+" + strings.Join(part[3:], ".")
		}
	} else {
		for i := range part {
			res := preReleaseSplitter.FindStringSubmatch(part[i])
			if res == nil {
				continue
			}
			number := res[1]
			preRelease := res[2]
			if preRelease != "" {
				if !strings.HasPrefix(preRelease, "-") {
					preRelease = "-" + preRelease
				}
				part[i] = number + preRelease
				break
			}
		}
		version = strings.Join(part, ".")
	}
	return version
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

func matchRevisionVersion(currentVersion *semver.Version, constraint string) (bool, error) {
	// Constraint may or may not have a revision.
	part := strings.Split(constraint, "+")
	conRev := 0
	c, err := semver.NewConstraint(part[0])
	if err != nil {
		return false, fmt.Errorf("failed create constraint: %s", err)
	}

	if len(part) > 1 {
		conRev, err = strconv.Atoi(part[1])
		if err != nil {
			return false, fmt.Errorf("failed to convert revision to integer: %s", err)
		}
	}

	curPatch := currentVersion.Patch()
	curRev, err := strconv.Atoi(currentVersion.Metadata())
	if err != nil {
		return false, fmt.Errorf("failed to convert revision to integer: %s", err)
	}

	// In case the revision of current is other than the one of the constraint we either  + or - on the  patch val.
	if curRev > conRev {
		curPatch++
	} else if curRev < conRev {
		curPatch--
	}

	v2, err := semver.NewVersion(fmt.Sprintf("%v.%v.%v", currentVersion.Major(), currentVersion.Minor(), curPatch))
	if err == nil {
		valid, _ := c.Validate(v2)
		if valid {
			return true, nil
		}
	}

	return false, nil
}
