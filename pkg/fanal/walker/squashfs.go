// Package walker provides filesystem walkers for Trivy artifact scanning.
//
// squashfs.go implements a reusable SquashFS walker built on diskfs/go-diskfs.
// It is shared by format-specific walkers (AppImage, Snap) so that SquashFS
// reading logic lives in exactly one place.
package walker

import (
	"io"
	"os"
	"strings"
	"time"

	diskfilebe "github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/filesystem/squashfs"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// WalkSquashFS opens the SquashFS image contained in sr and iterates every
// regular file, calling fn for each one.
//
// All file paths delivered to fn are slash-delimited and relative (no leading "/").
// This function is safe to call from multiple callers because diskfs reads the
// underlying io.SectionReader via goroutine-safe ReadAt calls.
func WalkSquashFS(sr *io.SectionReader, opt Option, fn WalkFunc) error {
	skipFiles := opt.SkipFiles
	skipDirs := append(opt.SkipDirs, defaultSkipDirs...)

	backend := diskfilebe.New(&squashFSBackendFile{sr}, true /* readOnly */)
	sqfs, err := squashfs.Read(backend, sr.Size(), 0, 0)
	if err != nil {
		return xerrors.Errorf("failed to read squashfs: %w", err)
	}

	return walkSquashFSDir(sqfs, "/", skipDirs, skipFiles, fn)
}

// walkSquashFSDir recursively walks dir inside the squashfs filesystem.
func walkSquashFSDir(fsys *squashfs.FileSystem, dir string, skipDirs, skipFiles []string, fn WalkFunc) error {
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return xerrors.Errorf("readdir %q: %w", dir, err)
	}

	for _, fi := range entries {
		name := fi.Name()
		var fullPath string
		if dir == "/" {
			fullPath = "/" + name
		} else {
			fullPath = dir + "/" + name
		}
		// Relative path used for skip-matching and passed to fn (no leading slash).
		relPath := strings.TrimPrefix(fullPath, "/")

		if fi.IsDir() {
			if utils.SkipPath(relPath, skipDirs) {
				continue
			}
			if err = walkSquashFSDir(fsys, fullPath, skipDirs, skipFiles, fn); err != nil {
				return err
			}
			continue
		}

		// Skip non-regular files (symlinks, block/char devices, sockets, etc.)
		if !fi.Mode().IsRegular() {
			continue
		}
		if utils.SkipPath(relPath, skipFiles) {
			continue
		}

		// Build the opener. Files are read into a cachedFile the first time the
		// opener is called, so that analysis goroutines never touch the underlying
		// io.SectionReader concurrently.
		capturedPath := fullPath
		capturedFI := fi
		opener := makeSquashFSOpener(fsys, capturedPath, capturedFI.Size())

		if err = fn(relPath, fi, opener); err != nil {
			return xerrors.Errorf("analyze file (%s): %w", relPath, err)
		}
	}
	return nil
}

// makeSquashFSOpener creates a lazy opener for a single squashfs file.
// The file content is read and cached on the first Open call.
func makeSquashFSOpener(fsys *squashfs.FileSystem, path string, size int64) func() (xio.ReadSeekCloserAt, error) {
	var cf *cachedFile
	return func() (xio.ReadSeekCloserAt, error) {
		if cf != nil {
			return cf.Open()
		}
		f, err := fsys.OpenFile(path, os.O_RDONLY)
		if err != nil {
			return nil, xerrors.Errorf("squashfs open (%s): %w", path, err)
		}
		cf = newCachedFile(size, f)
		return cf.Open()
	}
}

// squashFSBackendFile adapts *io.SectionReader to the fs.File interface
// that diskfs/go-diskfs backend/file.New requires.
// Write is a stub — we always open as read-only (readOnly=true).
type squashFSBackendFile struct {
	*io.SectionReader
}

func (s *squashFSBackendFile) Stat() (os.FileInfo, error) {
	return &squashFSFileInfo{size: s.Size()}, nil
}

func (s *squashFSBackendFile) Close() error { return nil }

func (s *squashFSBackendFile) Write(_ []byte) (int, error) {
	return 0, xerrors.Errorf("read-only squashfs: write not supported")
}

// squashFSFileInfo is a minimal os.FileInfo for the squashfs backend.
// diskfs only inspects Size() to validate the filesystem bounds.
type squashFSFileInfo struct{ size int64 }

func (i *squashFSFileInfo) Name() string       { return "squashfs" }
func (i *squashFSFileInfo) Size() int64        { return i.size }
func (i *squashFSFileInfo) Mode() os.FileMode  { return 0o444 }
func (i *squashFSFileInfo) ModTime() time.Time { return time.Time{} }
func (i *squashFSFileInfo) IsDir() bool        { return false }
func (i *squashFSFileInfo) Sys() interface{}   { return nil }
