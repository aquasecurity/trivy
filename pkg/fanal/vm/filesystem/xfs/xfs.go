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
	_, err := sr.Seek(0, io.SeekStart)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek offset error: %w", err)
	}
	ok := xfs.Check(&sr)
	if !ok {
		return nil, filesystem.ErrInvalidHeader
	}

	_, err = sr.Seek(0, io.SeekStart)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek offset error: %w", err)
	}
	f, err := xfs.NewFS(sr, cache)
	if err != nil {
		return nil, xerrors.Errorf("new xfs filesystem error: %w", err)
	}
	return f, nil
}
