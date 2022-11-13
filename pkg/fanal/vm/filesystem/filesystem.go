package filesystem

import (
	"golang.org/x/xerrors"
	"io"
	"io/fs"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
)

var (
	Filesystems      []Filesystem
	ErrInvalidHeader = xerrors.New("invalid Header error")
)

type Filesystem interface {
	New(sr io.SectionReader, cache vm.Cache) (fs.FS, error)
}

func RegisterFilesystem(filesystem Filesystem) {
	Filesystems = append(Filesystems, filesystem)
}
