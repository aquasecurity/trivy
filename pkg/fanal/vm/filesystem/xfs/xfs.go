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

func (x XFS) Try(rs io.ReadSeeker) (bool, error) {
	defer rs.Seek(0, io.SeekStart)
	ok := xfs.Check(rs)
	if !ok {
		return false, xerrors.Errorf("invalid xfs header")
	}

	return true, nil
}

func (x XFS) New(sr io.SectionReader, cache vm.Cache) (fs.FS, error) {
	f, err := xfs.NewFS(sr, cache)
	if err != nil {
		return nil, xerrors.Errorf("new xfs filesystem error: %w", err)
	}
	return f, nil
}
