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

func (fs *fileStat) Name() string       { return fs.name }
func (fs *fileStat) Size() int64        { return fs.size }
func (fs *fileStat) Mode() fs.FileMode  { return fs.mode }
func (fs *fileStat) IsDir() bool        { return fs.mode.IsDir() }
func (fs *fileStat) ModTime() time.Time { return fs.modTime }
func (fs *fileStat) Sys() any           { return &fs.sys }

func (fs *fileStat) Info() (fs.FileInfo, error) { return fs, nil }
func (fs *fileStat) Type() fs.FileMode          { return fs.mode }
