package extrafs

import (
	"io/fs"
	"os"
	"path/filepath"
)

/*
   Go does not currently support symlinks in io/fs.
   We work around this by wrapping the fs.FS returned by os.DirFS with our own type which bolts on the ReadLinkFS
*/

type OSFS interface {
	fs.FS
	fs.StatFS
}

type ReadLinkFS interface {
	ResolveSymlink(name, dir string) (string, error)
}

type FS interface {
	OSFS
	ReadLinkFS
}

type filesystem struct {
	root       string
	underlying OSFS
}

func OSDir(path string) FS {
	return &filesystem{
		root:       path,
		underlying: os.DirFS(path).(OSFS),
	}
}

func (f *filesystem) Open(name string) (fs.File, error) {
	return f.underlying.Open(name)
}

func (f *filesystem) Stat(name string) (fs.FileInfo, error) {
	return f.underlying.Stat(name)
}

func (f *filesystem) ResolveSymlink(name, dir string) (string, error) {
	link, err := os.Readlink(filepath.Join(f.root, dir, name))
	if err == nil {
		return filepath.Join(dir, link), nil
	}
	return name, nil
}
