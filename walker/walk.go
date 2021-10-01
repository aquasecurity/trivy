package walker

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/utils"
)

var (
	appDirs    = []string{".git", "vendor"}
	systemDirs = []string{"proc", "sys", "dev"}
)

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

	for _, skipDir := range append(skipDirs, systemDirs...) {
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
	if utils.StringInSlice(filePath, w.skipFiles) {
		return true
	}

	return false
}

func (w *walker) shouldSkipDir(dir string) bool {
	dir = filepath.ToSlash(dir)
	dir = strings.TrimLeft(dir, "/")

	// Skip application dirs (relative path)
	base := filepath.Base(dir)
	if utils.StringInSlice(base, appDirs) {
		return true
	}

	// Skip system dirs and specified dirs (absolute path)
	if utils.StringInSlice(dir, w.skipDirs) {
		return true
	}

	return false
}

// fileOnceOpener opens a file once and the content is shared so that some analyzers can use the same data
func (w *walker) fileOnceOpener(r io.Reader) func() ([]byte, error) {
	var once sync.Once
	var b []byte
	var err error

	return func() ([]byte, error) {
		once.Do(func() {
			b, err = io.ReadAll(r)
		})
		if err != nil {
			return nil, xerrors.Errorf("unable to read the file: %w", err)
		}
		return b, nil
	}
}
