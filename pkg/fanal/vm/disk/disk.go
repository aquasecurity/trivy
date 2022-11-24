package disk

import (
	"errors"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/disk/vmdk"
)

var (
	vmDisks = []Disk{
		vmdk.VMDK{},
	}
)

// Disk defines virtual machine disk images like VMDK, VDI and VHD.
type Disk interface {
	NewReader(rs io.ReadSeeker, cache vm.Cache) (*io.SectionReader, error)
}

func New(rs io.ReadSeeker, cache vm.Cache) (*io.SectionReader, error) {
	for _, disk := range vmDisks {
		vreader, err := disk.NewReader(rs, cache)
		if err != nil {
			if errors.Is(err, vm.ErrInvalidSignature) {
				continue
			}
			return nil, xerrors.Errorf("open virtual machine error: %w", err)
		}

		return vreader, nil
	}
	return nil, xerrors.New("virtual machine can not be detected")
}
