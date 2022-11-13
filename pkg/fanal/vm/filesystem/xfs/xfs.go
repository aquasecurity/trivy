package xfs

import (
	"io"
	"io/fs"

	"github.com/masahiro331/go-xfs-filesystem/xfs"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/filesystem"
)

func init() {
	filesystem.RegisterFilesystem(&XFS{})
}

type XFS struct{}

func (x XFS) New(sr io.SectionReader, cache vm.Cache) (fs.FS, error) {
	sr.Seek(0, io.SeekStart)
	ok := xfs.Check(&sr)
	if !ok {
		return nil, filesystem.ErrInvalidHeader
	}

	sr.Seek(0, io.SeekStart)
	f, err := xfs.NewFS(sr, cache)
	if err != nil {
		return nil, xerrors.Errorf("new xfs filesystem error: %w", err)
	}
	return f, nil
}
