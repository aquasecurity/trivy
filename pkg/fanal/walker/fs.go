package walker

import (
	"io/fs"
	"os"
	"path/filepath"

	swalker "github.com/saracen/walker"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
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

	if w.parallel <= 1 {
		// In series: fast, with higher CPU/memory
		return w.walkSlow(root, walkFn)
	}

	// In parallel: slow, with lower CPU/memory
	return w.walkFast(root, walkFn)
}

type fastWalkFunc func(pathname string, fi os.FileInfo) error

func (w FS) walkFast(root string, walkFn fastWalkFunc) error {
	// error function called for every error encountered
	errorCallbackOption := swalker.WithErrorCallback(w.errCallback)

	// Multiple goroutines stat the filesystem concurrently. The provided
	// walkFn must be safe for concurrent use.
	log.Logger.Debugf("Walk the file tree rooted at '%s' in parallel", root)
	if err := swalker.Walk(root, walkFn, errorCallbackOption); err != nil {
		return xerrors.Errorf("walk error: %w", err)
	}
	return nil
}

func (w FS) walkSlow(root string, walkFn fastWalkFunc) error {
	log.Logger.Debugf("Walk the file tree rooted at '%s' in series", root)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return w.errCallback(path, err)
		}
		info, err := d.Info()
		if err != nil {
			return xerrors.Errorf("file info error: %w", err)
		}
		return walkFn(path, info)
	})
	if err != nil {
		return xerrors.Errorf("walk dir error: %w", err)
	}
	return nil
}

// fileOpener returns a function opening a file.
func (w *walker) fileOpener(pathname string) func() (xio.ReadSeekCloserAt, error) {
	return func() (xio.ReadSeekCloserAt, error) {
		return os.Open(pathname)
	}
}
