package walker

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/log"
)

const defaultSizeThreshold = int64(100) << 20 // 200MB

var defaultSkipDirs = []string{
	"**/.git",
	"proc",
	"sys",
	"dev",
}

type Option struct {
	SkipFiles []string
	SkipDirs  []string
}

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error

func CleanSkipPaths(skipPaths []string) []string {
	return lo.Map(skipPaths, func(skipPath string, index int) string {
		skipPath = filepath.ToSlash(filepath.Clean(skipPath))
		return strings.TrimLeft(skipPath, "/")
	})
}

func SkipPath(path string, skipPaths []string) bool {
	path = strings.TrimLeft(path, "/")

	// skip files
	for _, pattern := range skipPaths {
		match, err := doublestar.Match(pattern, path)
		if err != nil {
			return false // return early if bad pattern
		} else if match {
			log.Debug("Skipping path", log.String("path", path))
			return true
		}
	}
	return false
}
