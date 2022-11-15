package vmdk

import (
	"io"

	"github.com/masahiro331/go-vmdk-parser/pkg/virtualization/vmdk"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
)

func init() {
	vm.RegisterVMReader(&VMDK{})
}

type VMDK struct{}

func (V VMDK) NewVMReader(rs io.ReadSeeker, cache vm.Cache) (*io.SectionReader, error) {
	_, err := rs.Seek(0, io.SeekStart)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek offset error: %w", err)
	}

	_, err = vmdk.Check(rs)
	if err != nil {
		return nil, vm.ErrInvalidSignature
	}

	_, err = rs.Seek(0, io.SeekStart)
	if err != nil {
		return nil, xerrors.Errorf("failed to seek offset error: %w", err)
	}
	reader, err := vmdk.Open(rs, cache)
	if err != nil {
		return nil, xerrors.Errorf("failed to open vmdk: %w", err)
	}
	return reader, nil
}
