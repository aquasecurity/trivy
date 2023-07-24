package mapfs

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/xerrors"

	xsync "github.com/aquasecurity/trivy/pkg/x/sync"
)

var separator = "/"

// file represents one of them:
// - an actual file
// - a virtual file
// - a virtual dir
type file struct {
	underlyingPath string // underlying file path
	data           []byte // virtual file, only either of 'path' or 'data' has a value.
	stat           fileStat
	files          xsync.Map[string, *file]
}

func (f *file) isVirtual() bool {
	return len(f.data) != 0 || f.stat.IsDir()
}

func (f *file) Open(name string) (fs.File, error) {
	if name == "" || name == "." {
		return f.open()
	}

	if sub, err := f.getFile(name); err == nil {
		return sub.open()
	}

	return nil, &fs.PathError{
		Op:   "open",
		Path: name,
		Err:  fs.ErrNotExist,
	}
}

func (f *file) open() (fs.File, error) {
	switch {
	case f.stat.IsDir(): // Directory
		entries, err := f.ReadDir(".")
		if err != nil {
			return nil, xerrors.Errorf("read dir error: %w", err)
		}
		return &mapDir{
			path:     f.underlyingPath,
			fileStat: f.stat,
			entry:    entries,
		}, nil
	case len(f.data) != 0: // Virtual file
		return &openMapFile{
			path:   f.stat.name,
			file:   f,
			offset: 0,
		}, nil
	default: // Real file
		return os.Open(f.underlyingPath)
	}
}

func (f *file) Remove(name string) error {
	if name == "" || name == "." {
		return nil
	}

	return f.removePath(name, false)
}

func (f *file) RemoveAll(name string) error {
	if name == "" || name == "." {
		return nil
	}

	return f.removePath(name, true)
}

func (f *file) removePath(name string, recursive bool) error {
	parts := strings.Split(name, separator)
	if len(parts) == 1 {
		sub, ok := f.files.Load(name)
		if !ok {
			return fs.ErrNotExist
		}
		if sub.files.Len() != 0 && !recursive {
			return fs.ErrInvalid
		}
		f.files.Delete(name)
		return nil
	}

	sub, err := f.getFile(parts[0])
	if err != nil {
		return err
	} else if !sub.stat.IsDir() {
		return fs.ErrNotExist
	}

	return sub.removePath(strings.Join(parts[1:], separator), recursive)
}

func (f *file) getFile(name string) (*file, error) {
	if name == "" || name == "." {
		return f, nil
	}
	parts := strings.Split(name, separator)
	if len(parts) == 1 {
		f, ok := f.files.Load(name)
		if ok {
			return f, nil
		}
		return nil, fs.ErrNotExist
	}

	sub, ok := f.files.Load(parts[0])
	if !ok || !sub.stat.IsDir() {
		return nil, fs.ErrNotExist
	}

	return sub.getFile(strings.Join(parts[1:], separator))
}

func (f *file) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "" || name == "." {
		var entries []fs.DirEntry
		var err error
		f.files.Range(func(name string, value *file) bool {
			if value.isVirtual() {
				entries = append(entries, &value.stat)
			} else {
				var fi os.FileInfo
				fi, err = os.Stat(value.underlyingPath)
				if err != nil {
					return false
				}
				entries = append(entries, &fileStat{
					name:    name,
					size:    fi.Size(),
					mode:    fi.Mode(),
					modTime: fi.ModTime(),
					sys:     fi.Sys(),
				})
			}
			return true
		})
		if err != nil {
			return nil, xerrors.Errorf("range error: %w", err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		return entries, nil
	}

	parts := strings.Split(name, separator)
	dir, ok := f.files.Load(parts[0])
	if !ok || !dir.stat.IsDir() {
		return nil, fs.ErrNotExist
	}
	return dir.ReadDir(strings.Join(parts[1:], separator))
}

func (f *file) MkdirAll(path string, perm fs.FileMode) error {
	parts := strings.Split(path, separator)

	if path == "" || path == "." {
		return nil
	}

	if perm&fs.ModeDir == 0 {
		perm |= fs.ModeDir
	}

	sub := &file{
		stat: fileStat{
			name:    parts[0],
			size:    0x100,
			modTime: time.Now(),
			mode:    perm,
		},
		files: xsync.Map[string, *file]{},
	}

	// Create the directory when the key is not present
	sub, loaded := f.files.LoadOrStore(parts[0], sub)
	if loaded && !sub.stat.IsDir() {
		return fs.ErrExist
	}

	if len(parts) == 1 {
		return nil
	}

	return sub.MkdirAll(strings.Join(parts[1:], separator), perm)
}

func (f *file) WriteFile(path, underlyingPath string) error {
	parts := strings.Split(path, separator)

	if len(parts) == 1 {
		f.files.Store(parts[0], &file{
			underlyingPath: underlyingPath,
		})
		return nil
	}

	dir, ok := f.files.Load(parts[0])
	if !ok || !dir.stat.IsDir() {
		return fs.ErrNotExist
	}

	return dir.WriteFile(strings.Join(parts[1:], separator), underlyingPath)
}

func (f *file) WriteVirtualFile(path string, data []byte, mode fs.FileMode) error {
	if mode&fs.ModeDir != 0 {
		return xerrors.Errorf("invalid perm: %v", mode)
	}
	parts := strings.Split(path, separator)

	if len(parts) == 1 {
		f.files.Store(parts[0], &file{
			data: data,
			stat: fileStat{
				name:    parts[0],
				size:    int64(len(data)),
				mode:    mode,
				modTime: time.Now(),
			},
		})
		return nil
	}

	dir, ok := f.files.Load(parts[0])
	if !ok || !dir.stat.IsDir() {
		return fs.ErrNotExist
	}

	return dir.WriteVirtualFile(strings.Join(parts[1:], separator), data, mode)
}

func (f *file) glob(pattern string) ([]string, error) {
	var entries []string
	parts := strings.Split(pattern, separator)

	var err error
	f.files.Range(func(name string, sub *file) bool {
		if ok, err := filepath.Match(parts[0], name); err != nil {
			return false
		} else if ok {
			if len(parts) == 1 {
				entries = append(entries, name)
			} else {
				subEntries, err := sub.glob(strings.Join(parts[1:], separator))
				if err != nil {
					return false
				}
				for _, sub := range subEntries {
					entries = append(entries, strings.Join([]string{
						name,
						sub,
					}, separator))
				}
			}
		}
		return true
	})
	if err != nil {
		return nil, xerrors.Errorf("range error: %w", err)
	}

	sort.Strings(entries)
	return entries, nil
}

// An openMapFile is a regular (non-directory) fs.File open for reading.
// ported from https://github.com/golang/go/blob/99bc53f5e819c2d2d49f2a56c488898085be3982/src/testing/fstest/mapfs.go
type openMapFile struct {
	path string
	*file
	offset int64
}

func (f *openMapFile) Stat() (fs.FileInfo, error) { return &f.file.stat, nil }

func (f *openMapFile) Close() error { return nil }

func (f *openMapFile) Read(b []byte) (int, error) {
	if f.offset >= int64(len(f.file.data)) {
		return 0, io.EOF
	}
	if f.offset < 0 {
		return 0, &fs.PathError{
			Op:   "read",
			Path: f.path,
			Err:  fs.ErrInvalid,
		}
	}
	n := copy(b, f.file.data[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *openMapFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0:
		// offset += 0
	case 1:
		offset += f.offset
	case 2:
		offset += int64(len(f.file.data))
	}
	if offset < 0 || offset > int64(len(f.file.data)) {
		return 0, &fs.PathError{
			Op:   "seek",
			Path: f.path,
			Err:  fs.ErrInvalid,
		}
	}
	f.offset = offset
	return offset, nil
}

func (f *openMapFile) ReadAt(b []byte, offset int64) (int, error) {
	if offset < 0 || offset > int64(len(f.file.data)) {
		return 0, &fs.PathError{
			Op:   "read",
			Path: f.path,
			Err:  fs.ErrInvalid,
		}
	}
	n := copy(b, f.file.data[offset:])
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

// A mapDir is a directory fs.File (so also fs.ReadDirFile) open for reading.
type mapDir struct {
	path string
	fileStat
	entry  []fs.DirEntry
	offset int
}

func (d *mapDir) Stat() (fs.FileInfo, error) { return &d.fileStat, nil }
func (d *mapDir) Close() error               { return nil }
func (d *mapDir) Read(_ []byte) (int, error) {
	return 0, &fs.PathError{
		Op:   "read",
		Path: d.path,
		Err:  fs.ErrInvalid,
	}
}

func (d *mapDir) ReadDir(count int) ([]fs.DirEntry, error) {
	n := len(d.entry) - d.offset
	if n == 0 && count > 0 {
		return nil, io.EOF
	}
	if count > 0 && n > count {
		n = count
	}
	list := make([]fs.DirEntry, n)
	for i := range list {
		list[i] = d.entry[d.offset+i]
	}
	d.offset += n
	return list, nil
}
