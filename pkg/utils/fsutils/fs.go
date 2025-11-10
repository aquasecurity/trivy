package fsutils

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	xdgDataHome = "XDG_DATA_HOME"
)

func HomeDir() string {
	dataHome := os.Getenv(xdgDataHome)
	if dataHome != "" {
		return dataHome
	}

	homeDir, _ := os.UserHomeDir()
	return homeDir
}

func TrivyHomeDir() string {
	return filepath.Join(HomeDir(), ".trivy")
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
	f, err := os.Stat(path)
	return err == nil && f.IsDir()
}

func FileExists(filename string) bool {
	f, err := os.Stat(filename)
	return err == nil && !f.IsDir()
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
			log.Debug("Walk error", log.FilePath(path), log.Err(err))
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
