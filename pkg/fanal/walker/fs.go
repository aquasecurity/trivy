package walker

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// FS is the filesystem walker
type FS struct{}

func NewFS() *FS {
	return &FS{}
}

// Walk walks the filesystem rooted at root, calling fn for each unfiltered file.
func (w *FS) Walk(root string, opt Option, fn WalkFunc) error {
	opt.SkipFiles = w.BuildSkipPaths(root, opt.SkipFiles)
	opt.SkipDirs = w.BuildSkipPaths(root, opt.SkipDirs)
	opt.SkipDirs = append(opt.SkipDirs, defaultSkipDirs...)
	opt.OnlyDirs = w.BuildSkipPaths(root, opt.OnlyDirs)

	walkDirFunc := w.WalkDirFunc(root, fn, opt)
	walkDirFunc = w.onError(walkDirFunc)

	// Walk the filesystem
	if err := filepath.WalkDir(root, walkDirFunc); err != nil {
		return xerrors.Errorf("walk dir error: %w", err)
	}

	return nil
}

func (w *FS) WalkDirFunc(root string, fn WalkFunc, opt Option) fs.WalkDirFunc {
	return func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// For exported rootfs (e.g. images/alpine/etc/alpine-release)
		relPath, err := filepath.Rel(root, filePath)
		if err != nil {
			return xerrors.Errorf("filepath rel (%s): %w", relPath, err)
		}
		relPath = filepath.ToSlash(relPath)

		// Skip unnecessary files
		switch {
		case d.IsDir():
			if utils.SkipPath(relPath, opt.SkipDirs) {
				return filepath.SkipDir
			}
			if utils.OnlyPath(relPath, opt.OnlyDirs) {
				return filepath.SkipDir
			}
			return nil
		case !d.Type().IsRegular():
			return nil
		case utils.SkipPath(relPath, opt.SkipFiles):
			return nil
		case utils.OnlyPath(relPath, opt.OnlyDirs):
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return xerrors.Errorf("file info error: %w", err)
		}

		if err = fn(relPath, info, fileOpener(filePath)); err != nil {
			return xerrors.Errorf("failed to analyze file: %w", err)
		}

		return nil
	}
}

func (w *FS) onError(wrapped fs.WalkDirFunc) fs.WalkDirFunc {
	return func(filePath string, d fs.DirEntry, err error) error {
		err = wrapped(filePath, d, err)
		switch {
		// Unwrap fs.SkipDir error
		case errors.Is(err, fs.SkipDir):
			return fs.SkipDir
		// Ignore permission errors
		case os.IsPermission(err):
			return nil
		case err != nil:
			// halt traversal on any other error
			return xerrors.Errorf("unknown error with %s: %w", filePath, err)
		}
		return nil
	}
}

// BuildSkipPaths builds correct patch for defaultSkipDirs and skipFiles
func (w *FS) BuildSkipPaths(base string, paths []string) []string {
	var relativePaths []string
	absBase, err := filepath.Abs(base)
	if err != nil {
		log.Warn("Failed to get an absolute path", log.String("base", base), log.Err(err))
		return nil
	}
	for _, path := range paths {
		// Supports three types of flag specification.
		// All of them are converted into the relative path from the root directory.
		// 1. Relative skip dirs/files from the root directory
		//     The specified dirs and files will be used as is.
		//       e.g. $ trivy fs --skip-dirs bar ./foo
		//     The skip dir from the root directory will be `bar/`.
		// 2. Relative skip dirs/files from the working directory
		//     The specified dirs and files wll be converted to the relative path from the root directory.
		//       e.g. $ trivy fs --skip-dirs ./foo/bar ./foo
		//     The skip dir will be converted to `bar/`.
		// 3. Absolute skip dirs/files
		//     The specified dirs and files wll be converted to the relative path from the root directory.
		//       e.g. $ trivy fs --skip-dirs /bar/foo/baz ./foo
		//     When the working directory is
		//       3.1 /bar: the skip dir will be converted to `baz/`.
		//       3.2 /hoge : the skip dir will be converted to `../../bar/foo/baz/`.

		absSkipPath, err := filepath.Abs(path)
		if err != nil {
			log.Warn("Failed to get an absolute path", log.String("base", base), log.Err(err))
			continue
		}
		rel, err := filepath.Rel(absBase, absSkipPath)
		if err != nil {
			log.Warn("Failed to get a relative path", log.String("from", base),
				log.String("to", path), log.Err(err))
			continue
		}

		var relPath string
		switch {
		case !filepath.IsAbs(path) && strings.HasPrefix(rel, ".."):
			// #1: Use the path as is
			relPath = path
		case !filepath.IsAbs(path) && !strings.HasPrefix(rel, ".."):
			// #2: Use the relative path from the root directory
			relPath = rel
		case filepath.IsAbs(path):
			// #3: Use the relative path from the root directory
			relPath = rel
		}
		relPath = filepath.ToSlash(relPath)
		relativePaths = append(relativePaths, relPath)
	}

	relativePaths = utils.CleanSkipPaths(relativePaths)
	return relativePaths
}

// fileOpener returns a function opening a file.
func fileOpener(filePath string) func() (xio.ReadSeekCloserAt, error) {
	return func() (xio.ReadSeekCloserAt, error) {
		return os.Open(filePath)
	}
}
