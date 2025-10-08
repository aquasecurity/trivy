package mapfs

import (
	"io/fs"
	"time"
)

// A fileStat is the implementation of FileInfo returned by Stat and Lstat.
// Ported from https://github.com/golang/go/blob/518889b35cb07f3e71963f2ccfc0f96ee26a51ce/src/os/types_unix.go
type fileStat struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
	sys     any
}

func (fstat *fileStat) Name() string       { return fstat.name }
func (fstat *fileStat) Size() int64        { return fstat.size }
func (fstat *fileStat) Mode() fs.FileMode  { return fstat.mode }
func (fstat *fileStat) IsDir() bool        { return fstat.mode.IsDir() }
func (fstat *fileStat) ModTime() time.Time { return fstat.modTime }
func (fstat *fileStat) Sys() any           { return &fstat.sys }

func (fstat *fileStat) Info() (fs.FileInfo, error) { return fstat, nil }
func (fstat *fileStat) Type() fs.FileMode          { return fstat.mode }
