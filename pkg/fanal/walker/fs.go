package walker

import (
	"errors"
	"golang.org/x/xerrors"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
)

type ErrorCallback func(pathname string, err error) error

type FS struct {
	walker
	opt Option
}

func NewFS(skipFiles, skipDirs []string, opt Option) FS {
	if opt.ErrCallback == nil {
		opt.ErrCallback = func(pathname string, err error) error {
			switch {
			// Unwrap fs.SkipDir error
			case errors.Is(err, fs.SkipDir):
				return fs.SkipDir
			// ignore permission errors
			case os.IsPermission(err):
				return nil
			}
			// halt traversal on any other error
			return xerrors.Errorf("unknown error with %s: %w", pathname, err)
		}
	}

	return FS{
		walker: newWalker(skipFiles, skipDirs),
		opt:    opt,
	}
}

// Walk walks the file tree rooted at root, calling WalkDirFunc for each file or
// directory in the tree, including root, but a directory to be ignored will be skipped.
func (w FS) Walk(root string, fn WalkFunc) error {
	walkDir := w.walkDirFunc(root, fn)
	err := filepath.WalkDir(root, func(filePath string, d fs.DirEntry, err error) error {
		if walkErr := walkDir(filePath, d, err); walkErr != nil {
			return w.opt.ErrCallback(filePath, walkErr)
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("walk dir error: %w", err)
	}
	return nil
}

func (w FS) walkDirFunc(root string, fn WalkFunc) fs.WalkDirFunc {
	return func(filePath string, d fs.DirEntry, err error) error {
		if err != nil {
			return w.opt.ErrCallback(filePath, err)
		}
		time.Sleep(w.opt.Delay)

		filePath = filepath.Clean(filePath)

		// For exported rootfs (e.g. images/alpine/etc/alpine-release)
		relPath, err := filepath.Rel(root, filePath)
		if err != nil {
			return xerrors.Errorf("filepath rel (%s): %w", relPath, err)
		}
		relPath = filepath.ToSlash(relPath)

		info, err := d.Info()
		if err != nil {
			return xerrors.Errorf("file info error: %w", err)
		}

		switch {
		case info.IsDir():
			if w.shouldSkipDir(relPath) {
				return filepath.SkipDir
			}
			return nil
		case !info.Mode().IsRegular():
			return nil
		case w.shouldSkipFile(relPath):
			return nil
		}

		if err = fn(relPath, info, w.fileOpener(filePath)); err != nil {
			return xerrors.Errorf("failed to analyze file: %w", err)
		}
		return nil
	}
}

// fileOpener returns a function opening a file.
func (w *walker) fileOpener(pathname string) func() (dio.ReadSeekCloserAt, error) {
	return func() (dio.ReadSeekCloserAt, error) {
		return os.Open(pathname)
	}
}
