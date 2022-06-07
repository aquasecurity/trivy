package walker

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/utils"
)

var (
	// These variables are exported so that a tool importing Trivy as a library can override these values.
	AppDirs    = []string{".git", "vendor"}
	SystemDirs = []string{"proc", "sys", "dev"}
)

const ThresholdSize = int64(200) << 20

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error

type walker struct {
	skipFiles []string
	skipDirs  []string
}

func newWalker(skipFiles, skipDirs []string) walker {
	var cleanSkipFiles, cleanSkipDirs []string
	for _, skipFile := range skipFiles {
		skipFile = filepath.Clean(filepath.ToSlash(skipFile))
		skipFile = strings.TrimLeft(skipFile, "/")
		cleanSkipFiles = append(cleanSkipFiles, skipFile)
	}

	for _, skipDir := range append(skipDirs, SystemDirs...) {
		skipDir = filepath.Clean(filepath.ToSlash(skipDir))
		skipDir = strings.TrimLeft(skipDir, "/")
		cleanSkipDirs = append(cleanSkipDirs, skipDir)
	}

	return walker{
		skipFiles: cleanSkipFiles,
		skipDirs:  cleanSkipDirs,
	}
}

func (w *walker) shouldSkipFile(filePath string) bool {
	filePath = filepath.ToSlash(filePath)
	filePath = strings.TrimLeft(filePath, "/")

	// skip files
	return utils.StringInSlice(filePath, w.skipFiles)
}

func (w *walker) shouldSkipDir(dir string) bool {
	dir = filepath.ToSlash(dir)
	dir = strings.TrimLeft(dir, "/")

	// Skip application dirs (relative path)
	base := filepath.Base(dir)
	if utils.StringInSlice(base, AppDirs) {
		return true
	}

	// Skip system dirs and specified dirs (absolute path)
	if utils.StringInSlice(dir, w.skipDirs) {
		return true
	}

	return false
}
