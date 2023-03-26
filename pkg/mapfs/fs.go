package mapfs

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/syncx"
)

type allFS interface {
	fs.ReadFileFS
	fs.ReadDirFS
	fs.StatFS
	fs.GlobFS
	fs.SubFS
}

// Make sure FS implements all the interfaces
var _ allFS = &FS{}

// FS is an in-memory filesystem
type FS struct {
	root *file
}

// New creates a new filesystem
func New() *FS {
	return &FS{
		root: &file{
			stat: fileStat{
				name:    ".",
				size:    0x100,
				modTime: time.Now(),
				mode:    0o0700 | fs.ModeDir,
			},
			files: syncx.Map[string, *file]{},
		},
	}
}

// Filter removes the specified skippedFiles and returns a new FS
func (m *FS) Filter(skippedFiles []string) (*FS, error) {
	if len(skippedFiles) == 0 {
		return m, nil
	}
	newFS := New()
	err := fs.WalkDir(m, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return newFS.MkdirAll(path, d.Type().Perm())
		}

		if slices.Contains(skippedFiles, path) {
			return nil
		}

		f, err := m.root.getFile(path)
		if err != nil {
			return xerrors.Errorf("unable to get %s: %w", path, err)
		}
		return newFS.WriteFile(path, f.path)
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error", err)
	}

	return newFS, nil
}

func (m *FS) CopyFilesUnder(dir string) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if d.IsDir() {
			return m.MkdirAll(path, d.Type())
		}
		return m.WriteFile(path, path)
	})
}

// Stat returns a FileInfo describing the file.
func (m *FS) Stat(name string) (fs.FileInfo, error) {
	name = cleanPath(name)
	f, err := m.root.getFile(name)
	if err != nil {
		return nil, &fs.PathError{
			Op:   "stat",
			Path: name,
			Err:  err,
		}
	}
	if f.isVirtual() {
		return &f.stat, nil
	}
	return os.Stat(f.path)
}

// ReadDir reads the named directory
// and returns a list of directory entries sorted by filename.
func (m *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	return m.root.ReadDir(cleanPath(name))
}

// Open opens the named file for reading.
func (m *FS) Open(name string) (fs.File, error) {
	return m.root.Open(cleanPath(name))
}

// WriteFile creates a mapping between path and underlyingPath.
func (m *FS) WriteFile(path, underlyingPath string) error {
	return m.root.WriteFile(cleanPath(path), underlyingPath)
}

// WriteVirtualFile writes the specified bytes to the named file. If the file exists, it will be overwritten.
func (m *FS) WriteVirtualFile(path string, data []byte, mode fs.FileMode) error {
	return m.root.WriteVirtualFile(cleanPath(path), data, mode)
}

// MkdirAll creates a directory named path,
// along with any necessary parents, and returns nil,
// or else returns an error.
// The permission bits perm (before umask) are used for all
// directories that MkdirAll creates.
// If path is already a directory, MkdirAll does nothing
// and returns nil.
func (m *FS) MkdirAll(path string, perm fs.FileMode) error {
	return m.root.MkdirAll(cleanPath(path), perm)
}

// ReadFile reads the named file and returns its contents.
// A successful call returns a nil error, not io.EOF.
// (Because ReadFile reads the whole file, the expected EOF
// from the final Read is not treated as an error to be reported.)
//
// The caller is permitted to modify the returned byte slice.
// This method should return a copy of the underlying data.
func (m *FS) ReadFile(name string) ([]byte, error) {
	f, err := m.root.Open(cleanPath(name))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

// Sub returns an FS corresponding to the subtree rooted at dir.
func (m *FS) Sub(dir string) (fs.FS, error) {
	d, err := m.root.getFile(cleanPath(dir))
	if err != nil {
		return nil, err
	}
	return &FS{
		root: d,
	}, nil
}

// Glob returns the names of all files matching pattern or nil
// if there is no matching file. The syntax of patterns is the same
// as in Match. The pattern may describe hierarchical names such as
// /usr/*/bin/ed (assuming the Separator is '/').
//
// Glob ignores file system errors such as I/O errors reading directories.
// The only possible returned error is ErrBadPattern, when pattern
// is malformed.
func (m *FS) Glob(pattern string) ([]string, error) {
	return m.root.glob(pattern)
}

// Remove deletes a file or directory from the filesystem
func (m *FS) Remove(path string) error {
	return m.root.Remove(cleanPath(path))
}

// RemoveAll deletes a file or directory and any children if present from the filesystem
func (m *FS) RemoveAll(path string) error {
	return m.root.RemoveAll(cleanPath(path))
}

func cleanPath(path string) string {
	// Return if the file path is a volume name only.
	// Otherwise, `filepath.Clean` changes "C:" to "C:." and
	// it will no longer match the pathname held by mapfs.
	if path == filepath.VolumeName(path) {
		return path
	}
	path = filepath.Clean(path)
	path = filepath.ToSlash(path)
	path = strings.TrimLeft(path, "/") // Remove the leading slash
	return path
}
