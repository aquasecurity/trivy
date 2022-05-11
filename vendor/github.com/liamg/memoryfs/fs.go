package memoryfs

import (
	"io"
	"io/fs"
	"io/ioutil"
	"strings"
	"time"
)

// FS is an in-memory filesystem
type FS struct {
	dir *dir
}

// New creates a new filesystem
func New() *FS {
	return &FS{
		dir: &dir{
			info: fileinfo{
				name:     ".",
				size:     0x100,
				modified: time.Now(),
				isDir:    true,
				mode:     0o700,
			},
			dirs:  map[string]*dir{},
			files: map[string]*file{},
		},
	}
}

// CloneFS allows you to take on fs.FS and wrap it in an fs that is writable
func CloneFS(base fs.FS) *FS {
	newFS := New()
	fs.WalkDir(base, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return newFS.MkdirAll(path, d.Type().Perm())
		}

		// Lazy write the files, holding onto the base FS to read the content on demand
		return newFS.WriteLazyFile(path, func() (io.Reader, error) {
			return base.Open(path)
		}, d.Type().Perm())
	})

	return newFS
}

// Stat returns a FileInfo describing the file.
func (m *FS) Stat(name string) (fs.FileInfo, error) {
	name = cleanse(name)
	if f, err := m.dir.getFile(name); err == nil {
		return f.stat(), nil
	}
	if f, err := m.dir.getDir(name); err == nil {
		return f.Stat()
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

// ReadDir reads the named directory
// and returns a list of directory entries sorted by filename.
func (m *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	return m.dir.ReadDir(cleanse(name))
}

// Open opens the named file for reading.
func (m *FS) Open(name string) (fs.File, error) {
	return m.dir.Open(cleanse(name))
}

// WriteFile writes the specified bytes to the named file. If the file exists, it will be overwritten.
func (m *FS) WriteFile(path string, data []byte, perm fs.FileMode) error {
	return m.dir.WriteFile(cleanse(path), data, perm)
}

// MkdirAll creates a directory named path,
// along with any necessary parents, and returns nil,
// or else returns an error.
// The permission bits perm (before umask) are used for all
// directories that MkdirAll creates.
// If path is already a directory, MkdirAll does nothing
// and returns nil.
func (m *FS) MkdirAll(path string, perm fs.FileMode) error {
	return m.dir.MkdirAll(cleanse(path), perm)
}

// ReadFile reads the named file and returns its contents.
// A successful call returns a nil error, not io.EOF.
// (Because ReadFile reads the whole file, the expected EOF
// from the final Read is not treated as an error to be reported.)
//
// The caller is permitted to modify the returned byte slice.
// This method should return a copy of the underlying data.
func (m *FS) ReadFile(name string) ([]byte, error) {
	f, err := m.dir.Open(cleanse(name))
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(f)
}

// Sub returns an FS corresponding to the subtree rooted at dir.
func (m *FS) Sub(dir string) (fs.FS, error) {
	d, err := m.dir.getDir(cleanse(dir))
	if err != nil {
		return nil, err
	}
	return &FS{
		dir: d,
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
	pattern = strings.ReplaceAll(pattern, "/", separator)
	return m.dir.glob(pattern)
}

// WriteLazyFile creates (or overwrites) the named file.
// The contents of the file are not set at this time, but are read on-demand later using the provided LazyOpener.
func (m *FS) WriteLazyFile(path string, opener LazyOpener, perm fs.FileMode) error {
	return m.dir.WriteLazyFile(cleanse(path), opener, perm)
}

// Remove deletes a file or directory from the filesystem
func (m *FS) Remove(path string) error {
	return m.dir.Remove(cleanse(path))
}

// RemoveAll deletes a file or directory and any children if present from the filesystem
func (m *FS) RemoveAll(path string) error {
	return m.dir.RemoveAll(cleanse(path))
}
