package disk

import (
	"errors"
	"fmt"
	"io"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
)

var (
	vmDisks = []Disk{
		VMDK{},
	}
)

// Disk defines virtual machine disk images like VMDK, VDI and VHD.
type Disk interface {
	NewReader(io.ReadSeeker, vm.Cache[string, []byte]) (*io.SectionReader, error)
}

func New(rs io.ReadSeeker, cache vm.Cache[string, []byte]) (*io.SectionReader, error) {

	for _, vmdisk := range vmDisks {
		var vreader, err = vmdisk.NewReader(rs, cache)
		if err != nil {
			if errors.Is(err, vm.ErrInvalidSignature) {
				continue
			}
			return nil, fmt.Errorf("open virtual machine error: %w", err)
		}

		return vreader, nil
	}
	return nil, errors.New("virtual machine can not be detected")
}
