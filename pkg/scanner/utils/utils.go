package utils

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"

	"github.com/knqyf263/go-version"
	"github.com/aquasecurity/trivy/pkg/log"
)

var (
	replacer = strings.NewReplacer(".alpha", "-alpha", ".beta", "-beta", ".rc", "-rc")
)

func MatchVersions(currentVersion *version.Version, rangeVersions []string) bool {
	for _, p := range rangeVersions {
		c, err := version.NewConstraint(replacer.Replace(p))
		if err != nil {
			log.Logger.Debug("NewConstraint", "error", err)
			return false
		}
		if c.Check(currentVersion) {
			return true
		}
	}
	return false
}

func FormatVersion(pkg analyzer.Package) string {
	return formatVersion(pkg.Epoch, pkg.Version, pkg.Release)
}

func FormatSrcVersion(pkg analyzer.Package) string {
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
