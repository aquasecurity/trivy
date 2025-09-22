package fsutils

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
)

// FileSource represents a file together with the filesystem it belongs to.
//
// It abstracts over virtual filesystems and real disk paths, allowing
// consistent access to files whether they reside in a virtual FS or on disk.
type FileSource struct {
	// FS is the filesystem used to access the file.
	// It is ignored if Path is absolute.
	FS fs.FS

	// Path is the relative or absolute path to the file in Unix-like format.
	// If Path is relative, FS is used; if absolute, the file is accessed directly on disk.
	Path string
}

func NewFileSource(fsys fs.FS, p string) FileSource {
	if filepath.IsAbs(p) {
		return FileSource{
			FS:   nil,
			Path: filepath.ToSlash(p),
		}
	}
	return FileSource{
		FS:   fsys,
		Path: path.Clean(p),
	}
}

func (f FileSource) String() string {
	if f.FS != nil {
		return f.Path
	}
	return f.osPath()
}

func (f FileSource) osPath() string {
	return filepath.FromSlash(f.Path)
}

// FSAndRelPath returns the fs.FS and relative path to use for opening the file.
// If the FileSource has an embedded FS, it is used as-is.
// For absolute paths without FS, it returns an os.DirFS rooted at the parent directory
// and the file name as the relative path.
func (f FileSource) FSAndRelPath() (fs.FS, string) {
	if f.FS != nil {
		return f.FS, f.Path
	}

	absPath := filepath.FromSlash(f.Path)
	return os.DirFS(filepath.Dir(absPath)), filepath.Base(absPath)
}

func (f FileSource) Join(elem ...string) FileSource {
	for i, e := range elem {
		elem[i] = filepath.ToSlash(e)
	}
	return FileSource{
		FS:   f.FS,
		Path: path.Join(append([]string{f.Path}, elem...)...),
	}
}

func (f FileSource) Stat() (fs.FileInfo, error) {
	if f.FS != nil {
		return fs.Stat(f.FS, f.Path)
	}
	return os.Stat(f.osPath())
}

func (f FileSource) Exists() (bool, error) {
	_, err := f.Stat()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (f FileSource) ReadFile() ([]byte, error) {
	if f.FS != nil {
		return fs.ReadFile(f.FS, f.Path)
	}
	return os.ReadFile(f.osPath())
}

func (f FileSource) Open() (fs.File, error) {
	if f.FS != nil {
		return f.FS.Open(f.Path)
	}
	return os.Open(f.osPath())
}

func (f FileSource) Dir() FileSource {
	return FileSource{
		FS:   f.FS,
		Path: path.Dir(f.Path),
	}
}

func (f FileSource) ReadDir() ([]fs.DirEntry, error) {
	if f.FS != nil {
		return fs.ReadDir(f.FS, f.Path)
	}
	return os.ReadDir(f.osPath())
}

func (f FileSource) walkDir(fn fs.WalkDirFunc) error {
	if f.FS != nil {
		return fs.WalkDir(f.FS, f.Path, fn)
	}

	return filepath.WalkDir(f.osPath(), fn)
}

func (f FileSource) WalkDirFS(fn func(FileSource, fs.DirEntry) error) error {
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return fn(FileSource{FS: f.FS, Path: filepath.ToSlash(path)}, d)
	}
	return f.walkDir(walkFn)
}

func WalkDirsFirstAlpha(root FileSource, fn func(FileSource, fs.DirEntry) error) error {
	var walk func(fileSrc FileSource) error
	walk = func(fileSrc FileSource) error {
		entries, err := fileSrc.ReadDir()
		if err != nil {
			return err
		}

		SortDirsFirstAlpha(entries)

		for _, entry := range entries {
			entrySrc := fileSrc.Join(entry.Name())
			if err := fn(entrySrc, entry); err != nil {
				return err
			}

			if entry.IsDir() {
				if err := walk(entrySrc); err != nil {
					return err
				}
			}
		}
		return nil
	}

	return walk(root)
}

func SortDirsFirstAlpha(entries []fs.DirEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
}
