package walker

import (
	"os"
	"path/filepath"

	swalker "github.com/saracen/walker"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/trivy/pkg/log"
)

type ErrorCallback func(pathname string, err error) error

type FS struct {
	walker
	parallel    int
	errCallback ErrorCallback
}

func NewFS(skipFiles, skipDirs []string, parallel int, errCallback ErrorCallback) FS {
	if errCallback == nil {
		errCallback = func(pathname string, err error) error {
			// ignore permission errors
			if os.IsPermission(err) {
				return nil
			}
			// halt traversal on any other error
			return xerrors.Errorf("unknown error with %s: %w", pathname, err)
		}
	}

	return FS{
		walker:      newWalker(skipFiles, skipDirs),
		parallel:    parallel,
		errCallback: errCallback,
	}
}

// Walk walks the file tree rooted at root, calling WalkFunc for each file or
// directory in the tree, including root, but a directory to be ignored will be skipped.
func (w FS) Walk(root string, fn WalkFunc) error {
	// walk function called for every path found
	walkFn := func(pathname string, fi os.FileInfo) error {
		pathname = filepath.Clean(pathname)

		// For exported rootfs (e.g. images/alpine/etc/alpine-release)
		relPath, err := filepath.Rel(root, pathname)
		if err != nil {
			return xerrors.Errorf("filepath rel (%s): %w", relPath, err)
		}
		relPath = filepath.ToSlash(relPath)

		switch {
		case fi.IsDir():
			if w.shouldSkipDir(relPath) {
				return filepath.SkipDir
			}
			return nil
		case !fi.Mode().IsRegular():
			return nil
		case w.shouldSkipFile(relPath):
			return nil
		}

		if err = fn(relPath, fi, w.fileOpener(pathname)); err != nil {
			return xerrors.Errorf("failed to analyze file: %w", err)
		}
		return nil
	}

	return w.walk(root, walkFn)
}

type fastWalkFunc func(pathname string, fi os.FileInfo) error

func (w FS) walk(root string, walkFn fastWalkFunc, walkOpts ...swalker.Option) error {
	// error function called for every error encountered
	errorCallbackOption := swalker.WithErrorCallback(w.errCallback)

	if w.parallel <= 1 {
		log.Logger.Debugf("Walk the file tree rooted at '%s' in series", root)
	} else {
		// Multiple goroutines stat the filesystem concurrently. The provided
		// walkFn must be safe for concurrent use.
		log.Logger.Debugf("Walk the file tree rooted at '%s' in parallel", root)
	}

	if err := swalker.Walk(root, walkFn, append(walkOpts, errorCallbackOption)...); err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}
	return nil
}

// fileOpener returns a function opening a file.
func (w *walker) fileOpener(pathname string) func() (dio.ReadSeekCloserAt, error) {
	return func() (dio.ReadSeekCloserAt, error) {
		return os.Open(pathname)
	}
}
