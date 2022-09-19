package filesystem

import (
	"io"
	"io/fs"
)

var Filesystems []Filesystem

type Filesystem interface {
	Try(rs io.ReadSeeker) (bool, error)
	New(sr io.SectionReader) (fs.FS, error)
}

func RegisterFilesystem(filesystem Filesystem) {
	Filesystems = append(Filesystems, filesystem)
}
