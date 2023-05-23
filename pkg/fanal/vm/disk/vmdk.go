package disk

import (
	"errors"
	"io"

	"github.com/masahiro331/go-vmdk-parser/pkg/virtualization/vmdk"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
)

type VMDK struct{}

func (V VMDK) NewReader(rs io.ReadSeeker, cache vm.Cache[string, []byte]) (*io.SectionReader, error) {
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("seek error: %w", err)
	}

	if _, err := vmdk.Check(rs); err != nil {
		return nil, vm.ErrInvalidSignature
	}

	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, xerrors.Errorf("seek error: %w", err)
	}

	reader, err := vmdk.Open(rs, cache)
	if err != nil {
		if errors.Is(err, vmdk.ErrUnSupportedType) {
			return nil, xerrors.Errorf("%s: %w", err.Error(), vm.ErrUnsupportedType)
		}
		return nil, xerrors.Errorf("failed to open vmdk: %w", err)
	}
	return reader, nil
}
