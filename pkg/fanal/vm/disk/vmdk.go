package disk

import (
	"errors"
	"fmt"
	"io"

	"github.com/masahiro331/go-vmdk-parser/pkg/virtualization/vmdk"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
)

type VMDK struct{}

func (VMDK) NewReader(rs io.ReadSeeker, cache vm.Cache[string, []byte]) (*io.SectionReader, error) {
	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek error: %w", err)
	}

	if _, err := vmdk.Check(rs); err != nil {
		return nil, vm.ErrInvalidSignature
	}

	if _, err := rs.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek error: %w", err)
	}

	reader, err := vmdk.Open(rs, cache)
	if err != nil {
		if errors.Is(err, vmdk.ErrUnSupportedType) {
			return nil, fmt.Errorf("%s: %w", err.Error(), vm.ErrUnsupportedType)
		}
		return nil, fmt.Errorf("failed to open vmdk: %w", err)
	}
	return reader, nil
}
