package utils

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/knqyf263/go-version"
	version2 "github.com/mcuadros/go-version"
)

var (
	replacer = strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc")
)

func MatchVersions(currentVersion *version.Version, rangeVersions []string) bool {
	for i := range rangeVersions {
		rangeVersions[i] = replacer.Replace(rangeVersions[i])
		c, err := version.NewConstraint(replacer.Replace(rangeVersions[i]))
		if err != nil {
			log.Logger.Debug("NewConstraint", "error", err)
			return false
		}
		if c.Check(currentVersion) {
			return true
		}
		c2 := version2.NewConstrainGroupFromString(rangeVersions[i])
		if c2.Match(currentVersion.String()) {
			return true
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
