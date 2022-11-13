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
	rs.Seek(0, io.SeekStart)
	_, err := vmdk.Check(rs)
	if err != nil {
		return nil, vm.ErrInvalidSignature
	}

	rs.Seek(0, io.SeekStart)
	reader, err := vmdk.Open(rs, cache)
	if err != nil {
		return nil, xerrors.Errorf("failed to open vmdk: %w", err)
	}
	return reader, nil
}
