package vmdk

import (
	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/hashicorp/go-multierror"
	"github.com/masahiro331/go-vmdk-parser/pkg/virtualization/vmdk"
	"golang.org/x/xerrors"
	"io"
)

func init() {
	vm.RegisterVMParser(&VMDK{})
}

type VMDK struct{}

func (V VMDK) Try(rs io.ReadSeeker) (bool, error) {
	var errs error
	ok, err := vmdk.Check(rs)
	if err != nil {
		errs = multierror.Append(errs, err)
	}
	rs.Seek(0, io.SeekStart)
	return ok, errs
}

func (V VMDK) Open(rs io.ReadSeeker) (*io.SectionReader, error) {
	reader, err := vmdk.Open(rs)
	if err != nil {
		return nil, xerrors.Errorf("failed to open vmdk: %w", err)
	}
	return reader, nil
}
