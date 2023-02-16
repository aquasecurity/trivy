package mapfs

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/syncx"
)

var separator = string(os.PathSeparator)

type file struct {
	path  string // underlying file path
	stat  fileStat
	files syncx.Map[string, *file]
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
	return os.Open(f.path)
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
			if value.stat.IsDir() {
				entries = append(entries, &value.stat)
			} else {
				var fi os.FileInfo
				fi, err = os.Stat(value.path)
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

	sub, ok := f.files.Load(parts[0])
	if ok && !sub.stat.IsDir() {
		return fs.ErrExist
	} else if !ok {
		if perm&fs.ModeDir == 0 {
			perm |= fs.ModeDir
		}

		sub = &file{
			stat: fileStat{
				name:    parts[0],
				size:    0x100,
				modTime: time.Now(),
				mode:    perm,
			},
			files: syncx.Map[string, *file]{},
		}
		f.files.Store(parts[0], sub)
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
			path: underlyingPath,
		})
		return nil
	}

	dir, ok := f.files.Load(parts[0])
	if !ok || !dir.stat.IsDir() {
		return fs.ErrNotExist
	}

	return dir.WriteFile(strings.Join(parts[1:], separator), underlyingPath)
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

	return entries, nil
}
