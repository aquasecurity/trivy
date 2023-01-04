package filesystem

import (
	"io"
	"io/fs"

	"github.com/masahiro331/go-ext4-filesystem/ext4"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
)

type EXT4 struct{}

func (e EXT4) New(sr io.SectionReader, cache vm.Cache[string, any]) (fs.FS, error) {
	_, err := sr.Seek(0, io.SeekStart)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek offset error: %w", err)
	}
	ok := ext4.Check(&sr)
	if !ok {
		return nil, ErrInvalidHeader
	}

	_, err = sr.Seek(0, io.SeekStart)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek offset error: %w", err)
	}
	f, err := ext4.NewFS(sr, cache)
	if err != nil {
		return nil, xerrors.Errorf("new ext4 filesystem error: %w", err)
	}
	return f, nil
}
