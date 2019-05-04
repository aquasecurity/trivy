package utils

import (
	"fmt"
	"strings"

	"github.com/knqyf263/fanal/analyzer"

	"github.com/knqyf263/go-version"
	"github.com/knqyf263/trivy/pkg/log"
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
	v := pkg.Version
	if pkg.Release != "" {
		v = fmt.Sprintf("%s-%s", v, pkg.Release)
	}
	if pkg.Epoch != 0 {
		v = fmt.Sprintf("%d:%s", pkg.Epoch, v)
	}
	return v
}
