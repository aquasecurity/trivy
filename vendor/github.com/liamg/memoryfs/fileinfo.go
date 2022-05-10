package memoryfs

import (
	"io/fs"
	"time"
)

type fileinfo struct {
	name     string
	size     int64
	modified time.Time
	isDir    bool
	mode     fs.FileMode
}

// Name is the base name of the file (without directory)
func (f fileinfo) Name() string {
	return f.name
}

// Size is the size of the file in bytes (not reliable for lazy loaded files)
func (f fileinfo) Size() int64 {
	return f.size
}

// Mode is the fs.FileMode of the file
func (f fileinfo) Mode() fs.FileMode {
	return f.mode
}

// Info attempts to provide the fs.FileInfo for the file
func (f fileinfo) Info() (fs.FileInfo, error) {
	return f, nil
}

// Type returns the type bits for the entry.
// The type bits are a subset of the usual FileMode bits, those returned by the FileMode.Type method.
func (f fileinfo) Type() fs.FileMode {
	return f.Mode().Type()
}

// ModTime is the modification time of the file (not reliable for lazy loaded files)
func (f fileinfo) ModTime() time.Time {
	return f.modified
}

// IsDir reports whether the entry describes a directory.
func (f fileinfo) IsDir() bool {
	return f.isDir
}

// Sys is the underlying data source of the file (always nil)
func (f fileinfo) Sys() interface{} {
	return nil
}
