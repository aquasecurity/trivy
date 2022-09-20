package filesystem

import (
	"io"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
)

var Filesystems []Filesystem

type Filesystem interface {
	Try(rs io.ReadSeeker) (bool, error)
	New(sr io.SectionReader, cache vm.Cache) (fs.FS, error)
}

func RegisterFilesystem(filesystem Filesystem) {
	Filesystems = append(Filesystems, filesystem)
}
