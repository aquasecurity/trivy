package pom

import (
	"strings"
)

var obsoleteRemoteRepoPaths = []string{
	"oss.sonatype.org",
}

func isObsoleteRepo(repo string) bool {
	for _, obsoleteRepo := range obsoleteRemoteRepoPaths {
		if strings.Contains(repo, obsoleteRepo) {
			return true
		}
	}
	return false
}
