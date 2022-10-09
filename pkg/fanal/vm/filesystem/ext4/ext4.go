package ext4

import (
	"io"
	"io/fs"

	"github.com/masahiro331/go-ext4-filesystem/ext4"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/filesystem"
)

func init() {
	filesystem.RegisterFilesystem(&EXT4{})
}

type EXT4 struct{}

func (e EXT4) Try(rs io.ReadSeeker) (bool, error) {
	defer rs.Seek(0, io.SeekStart)
	ok := ext4.Check(rs)
	if !ok {
		return false, xerrors.Errorf("invalid ext4 header")
	}

	return true, nil
}

func (e EXT4) New(sr io.SectionReader, cache vm.Cache) (fs.FS, error) {
	f, err := ext4.NewFS(sr, cache)
	if err != nil {
		return nil, xerrors.Errorf("new ext4 filesystem error: %w", err)
	}
	return f, nil
}
