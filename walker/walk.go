package walker

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"

	"github.com/aquasecurity/fanal/analyzer/library"
	"github.com/aquasecurity/fanal/utils"
)

var (
	ignoreDirs       = []string{".git"}
	ignoreSystemDirs = []string{"proc", "sys"}
)

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error

func isIgnored(filePath string, skipDirectories []string) bool {
	filePath = strings.TrimLeft(filepath.Clean(filePath), utils.PathSeparator)
	for _, path := range strings.Split(filePath, utils.PathSeparator) {
		if utils.StringInSlice(path, library.IgnoreDirs) {
			return true
		}
		if utils.StringInSlice(path, ignoreDirs) {
			return true
		}
	}

	// skip user-specified directories
	for _, dir := range skipDirectories {
		dir = filepath.Clean(dir)
		if strings.HasPrefix(filePath, strings.TrimLeft(dir, utils.PathSeparator)) {
			return true
		}
	}

	// skip system directories such as /sys and /proc
	for _, ignore := range ignoreSystemDirs {
		if strings.HasPrefix(filePath, ignore) {
			return true
		}
	}

	return false
}
