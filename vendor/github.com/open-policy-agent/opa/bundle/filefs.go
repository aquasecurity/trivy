//go:build go1.16
// +build go1.16

package bundle

import (
	"fmt"
	"io"
	"io/fs"
	"sync"
)

const (
	defaultFSLoaderRoot = "."
)

type dirLoaderFS struct {
	sync.Mutex
	filesystem fs.FS
	files      []string
	idx        int
}

// NewFSLoader returns a basic DirectoryLoader implementation
// that will load files from a fs.FS interface
func NewFSLoader(filesystem fs.FS) (DirectoryLoader, error) {
	d := dirLoaderFS{
		filesystem: filesystem,
	}

	err := fs.WalkDir(d.filesystem, defaultFSLoaderRoot, d.walkDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list files: %w", err)
	}

	return &d, nil
}

func (d *dirLoaderFS) walkDir(path string, dirEntry fs.DirEntry, err error) error {
	if err != nil {
		return err
	}

	if dirEntry != nil && dirEntry.Type().IsRegular() {
		d.files = append(d.files, path)
	}

	return nil
}

// NextFile iterates to the next file in the directory tree
// and returns a file Descriptor for the file.
func (d *dirLoaderFS) NextFile() (*Descriptor, error) {
	d.Lock()
	defer d.Unlock()

	// If done reading files then just return io.EOF
	// errors for each NextFile() call
	if d.idx >= len(d.files) {
		return nil, io.EOF
	}

	fileName := d.files[d.idx]
	d.idx++

	fh, err := d.filesystem.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", fileName, err)
	}

	fileNameWithSlash := fmt.Sprintf("/%s", fileName)
	f := newDescriptor(fileNameWithSlash, fileNameWithSlash, fh).withCloser(fh)
	return f, nil
}
