package walker

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

var (
	// These variables are exported so that a tool importing Trivy as a library can override these values.
	AppDirs    = []string{".git"}
	SystemDirs = []string{"proc", "sys", "dev"}
)

const (
	defaultSizeThreshold = int64(200) << 20 // 200MB
	slowSizeThreshold    = int64(200) << 20 // 10KB
)

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error

type walker struct {
	skipFiles []string
	skipDirs  []string
	slow      bool
}

func newWalker(skipFiles, skipDirs []string, slow bool) walker {
	var cleanSkipFiles, cleanSkipDirs []string
	for _, skipFile := range skipFiles {
		skipFile = filepath.ToSlash(filepath.Clean(skipFile))
		skipFile = strings.TrimLeft(skipFile, "/")
		cleanSkipFiles = append(cleanSkipFiles, skipFile)
	}

	for _, skipDir := range append(skipDirs, SystemDirs...) {
		skipDir = filepath.ToSlash(filepath.Clean(skipDir))
		skipDir = strings.TrimLeft(skipDir, "/")
		cleanSkipDirs = append(cleanSkipDirs, skipDir)
	}

	return walker{
		skipFiles: cleanSkipFiles,
		skipDirs:  cleanSkipDirs,
		slow:      slow,
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
