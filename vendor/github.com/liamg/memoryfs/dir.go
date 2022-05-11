package memoryfs

import (
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var separator = string(filepath.Separator)

type dir struct {
	sync.RWMutex
	info  fileinfo
	dirs  map[string]*dir
	files map[string]*file
}

func (d *dir) Open(name string) (fs.File, error) {

	if name == "" || name == "." {
		return d, nil
	}

	if f, err := d.getFile(name); err == nil {
		return f.open()
	}

	if f, err := d.getDir(name); err == nil {
		return f, nil
	}

	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (d *dir) Remove(name string) error {
	if name == "" || name == "." {
		return nil
	}

	return d.removePath(name, false)
}

func (d *dir) RemoveAll(name string) error {
	if name == "" || name == "." {
		return nil
	}

	return d.removePath(name, true)
}

func (d *dir) Stat() (fs.FileInfo, error) {
	d.RLock()
	defer d.RUnlock()
	return d.info, nil
}

func (d *dir) removePath(name string, recursive bool) error {

	parts := strings.Split(name, separator)
	if len(parts) == 1 {
		d.RLock()
		_, ok := d.files[name]
		d.RUnlock()
		if ok {
			delete(d.files, name)
			return nil
		}

		if sub, err := d.getDir(parts[0]); err == nil {
			d.Lock()
			defer d.Unlock()
			if len(sub.dirs) == 0 && len(sub.files) == 0 {
				delete(d.dirs, parts[0])
				return nil
			} else if recursive {
				for _, s := range sub.dirs {
					sub.removePath(s.info.name, recursive)
				}
				for _, f := range sub.files {
					sub.removePath(f.info.name, recursive)
				}
				delete(d.dirs, parts[0])
				return nil
			}
			return fs.ErrInvalid
		}
		return fs.ErrNotExist
	}

	sub, err := d.getDir(parts[0])
	if err != nil {
		return err
	}

	return sub.removePath(strings.Join(parts[1:], separator), recursive)
}

func (d *dir) getFile(name string) (*file, error) {

	parts := strings.Split(name, separator)
	if len(parts) == 1 {
		d.RLock()
		f, ok := d.files[name]
		d.RUnlock()
		if ok {
			return f, nil
		}
		return nil, fs.ErrNotExist
	}

	sub, err := d.getDir(parts[0])
	if err != nil {
		return nil, err
	}

	return sub.getFile(strings.Join(parts[1:], separator))
}

func (d *dir) getDir(name string) (*dir, error) {

	if name == "" {
		return d, nil
	}

	parts := strings.Split(name, separator)

	d.RLock()
	f, ok := d.dirs[parts[0]]
	d.RUnlock()
	if ok {
		return f.getDir(strings.Join(parts[1:], separator))
	}

	return nil, fs.ErrNotExist
}

func (d *dir) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "" {
		var entries []fs.DirEntry
		d.RLock()
		for _, file := range d.files {
			stat := file.stat()
			entries = append(entries, stat.(fs.DirEntry))
		}
		for _, dir := range d.dirs {
			stat, _ := dir.Stat()
			entries = append(entries, stat.(fs.DirEntry))
		}
		d.RUnlock()
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		return entries, nil
	}

	parts := strings.Split(name, separator)

	d.RLock()
	dir, ok := d.dirs[parts[0]]
	d.RUnlock()
	if !ok {
		return nil, fs.ErrNotExist
	}
	return dir.ReadDir(strings.Join(parts[1:], separator))
}

func (d *dir) Read(_ []byte) (int, error) {
	return 0, fs.ErrInvalid
}

func (d *dir) Close() error {
	return nil
}

func (d *dir) MkdirAll(path string, perm fs.FileMode) error {
	parts := strings.Split(path, separator)

	if path == "" {
		return nil
	}

	d.RLock()
	_, ok := d.files[parts[0]]
	d.RUnlock()
	if ok {
		return fs.ErrExist
	}

	d.Lock()
	if _, ok := d.dirs[parts[0]]; !ok {
		d.dirs[parts[0]] = &dir{
			info: fileinfo{
				name:     parts[0],
				size:     0x100,
				modified: time.Now(),
				isDir:    true,
				mode:     perm,
			},
			dirs:  map[string]*dir{},
			files: map[string]*file{},
		}
	}
	d.info.modified = time.Now()
	d.Unlock()

	if len(parts) == 1 {
		return nil
	}

	d.RLock()
	defer d.RUnlock()
	return d.dirs[parts[0]].MkdirAll(strings.Join(parts[1:], separator), perm)
}

func (d *dir) WriteFile(path string, data []byte, perm fs.FileMode) error {
	parts := strings.Split(path, separator)

	if len(parts) == 1 {
		max := bufferSize
		if len(data) > max {
			max = len(data)
		}
		buffer := make([]byte, len(data), max)
		copy(buffer, data)
		d.Lock()
		defer d.Unlock()
		if existing, ok := d.files[parts[0]]; ok {
			if err := existing.overwrite(buffer, perm); err != nil {
				return err
			}
		} else {
			newFile := &file{
				info: fileinfo{
					name:     parts[0],
					size:     int64(len(buffer)),
					modified: time.Now(),
					isDir:    false,
					mode:     perm,
				},
				content: buffer,
			}
			newFile.opener = func() (io.Reader, error) {
				return &lazyAccess{
					file: newFile,
				}, nil
			}
			d.files[parts[0]] = newFile
		}
		return nil
	}

	d.RLock()
	_, ok := d.dirs[parts[0]]
	d.RUnlock()
	if !ok {
		return fs.ErrNotExist
	}

	d.RLock()
	defer d.RUnlock()
	return d.dirs[parts[0]].WriteFile(strings.Join(parts[1:], separator), data, perm)
}

func (d *dir) glob(pattern string) ([]string, error) {

	var entries []string
	parts := strings.Split(pattern, separator)

	d.RLock()
	defer d.RUnlock()
	for name, dir := range d.dirs {
		if ok, err := filepath.Match(parts[0], name); err != nil {
			return nil, err
		} else if ok {
			if len(parts) == 1 {
				entries = append(entries, name)
			} else {
				subEntries, err := dir.glob(strings.Join(parts[1:], separator))
				if err != nil {
					return nil, err
				}
				for _, sub := range subEntries {
					entries = append(entries, strings.Join([]string{name, sub}, separator))
				}
			}
		}
	}

	if len(parts) == 1 {
		for name := range d.files {
			if ok, err := filepath.Match(parts[0], name); err != nil {
				return nil, err
			} else if ok {
				entries = append(entries, name)
			}
		}
	}

	return entries, nil
}

func (d *dir) WriteLazyFile(path string, opener LazyOpener, perm fs.FileMode) error {
	parts := strings.Split(path, separator)

	if len(parts) == 1 {
		d.Lock()
		defer d.Unlock()
		d.files[parts[0]] = &file{
			info: fileinfo{
				name:     parts[0],
				size:     0,
				modified: time.Now(),
				isDir:    false,
				mode:     perm,
			},
			opener: opener,
		}
		return nil
	}

	d.RLock()
	_, ok := d.dirs[parts[0]]
	d.RUnlock()
	if !ok {
		return fs.ErrNotExist
	}

	d.RLock()
	defer d.RUnlock()
	return d.dirs[parts[0]].WriteLazyFile(strings.Join(parts[1:], separator), opener, perm)
}
