package vm

import (
	"errors"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm/vmdk"
)

var (
	vmDisks = []Disk{
		vmdk.VMDK{},
	}

	ErrInvalidSignature = xerrors.New("invalid signature error")
	ErrUnsupportedType  = xerrors.New("unsupported type error")
)

// Disk defines virtual machine disk images like VMDK, VDI and VHD.
type Disk interface {
	NewReader(rs io.ReadSeeker, cache Cache) (*io.SectionReader, error)
}

type Cache interface {
	// Add stores data in the cache
	Add(key, value interface{}) bool

	// Get returns key's value from the cache
	Get(key interface{}) (value interface{}, ok bool)
}

func New(rs io.ReadSeeker, cache Cache) (*io.SectionReader, error) {
	for _, disk := range vmDisks {
		vreader, err := disk.NewReader(rs, cache)
		if err != nil {
			if errors.Is(err, ErrInvalidSignature) {
				continue
			}
			return nil, xerrors.Errorf("open virtual machine error: %w", err)
		}

		return vreader, nil
	}
	return nil, xerrors.New("virtual machine can not be detected")
}
