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

func (e EXT4) New(sr io.SectionReader, cache vm.Cache) (fs.FS, error) {
	sr.Seek(0, io.SeekStart)
	ok := ext4.Check(&sr)
	if !ok {
		return nil, filesystem.ErrInvalidHeader
	}

	sr.Seek(0, io.SeekStart)
	f, err := ext4.NewFS(sr, cache)
	if err != nil {
		return nil, xerrors.Errorf("new ext4 filesystem error: %w", err)
	}
	return f, nil
}
