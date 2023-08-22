package fsutils

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	xdgDataHome = "XDG_DATA_HOME"
)

var cacheDir string

// defaultCacheDir returns/creates the cache-dir to be used for trivy operations
func defaultCacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy")
}

// CacheDir returns the directory used for caching
func CacheDir() string {
	if cacheDir == "" {
		return defaultCacheDir()
	}
	return cacheDir
}

// SetCacheDir sets the trivy cacheDir
func SetCacheDir(dir string) {
	cacheDir = dir
}

func HomeDir() string {
	dataHome := os.Getenv(xdgDataHome)
	if dataHome != "" {
		return dataHome
	}

	homeDir, _ := os.UserHomeDir()
	return homeDir
}

// CopyFile copies the file content from scr to dst
func CopyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, xerrors.Errorf("file (%s) stat error: %w", src, err)
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	n, err := io.Copy(destination, source)
	return n, err
}

func DirExists(path string) bool {
	if f, err := os.Stat(path); os.IsNotExist(err) || !f.IsDir() {
		return false
	}
	return true
}

type WalkDirRequiredFunc func(path string, d fs.DirEntry) bool

type WalkDirFunc func(path string, d fs.DirEntry, r io.Reader) error

func WalkDir(fsys fs.FS, root string, required WalkDirRequiredFunc, fn WalkDirFunc) error {
	return fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if !d.Type().IsRegular() || !required(path, d) {
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return xerrors.Errorf("file open error: %w", err)
		}
		defer f.Close()

		if err = fn(path, d, f); err != nil {
			log.Logger.Debugw("Walk error", zap.String("file_path", path), zap.Error(err))
		}
		return nil
	})
}

func RequiredExt(exts ...string) WalkDirRequiredFunc {
	return func(filePath string, _ fs.DirEntry) bool {
		return slices.Contains(exts, filepath.Ext(filePath))
	}
}

func RequiredFile(fileNames ...string) WalkDirRequiredFunc {
	return func(filePath string, _ fs.DirEntry) bool {
		return slices.Contains(fileNames, filepath.Base(filePath))
	}
}
