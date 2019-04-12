package utils

import (
	"strings"

	"github.com/hashicorp/go-version"
	"github.com/knqyf263/trivy/pkg/logger"
)

var (
	replacer = strings.NewReplacer(".beta", "-beta", ".rc", "-rc")
)

func MatchVersions(currentVersion *version.Version, rangeVersions []string) bool {
	for _, p := range rangeVersions {
		c, err := version.NewConstraint(replacer.Replace(p))
		if err != nil {
			logger.Logger.Debug("NewConstraint", "error", err, "constraint", p)
			return false
		}
		if c.Check(currentVersion) {
			return true
		}
	}
	return false
}
