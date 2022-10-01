package vm

import (
	"io"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"
)

var Readers []Reader

type Reader interface {
	Try(rs io.ReadSeeker) (bool, error)
	NewVMReader(rs io.ReadSeeker, cache Cache) (*io.SectionReader, error)
}

type Cache interface {
	// Add cache data
	Add(key, value interface{}) bool

	// Get returns key's value from the cache
	Get(key interface{}) (value interface{}, ok bool)
}

func RegisterVMReader(vm Reader) {
	Readers = append(Readers, vm)
}

type VM struct {
	*io.SectionReader
}

func New(rs io.ReadSeeker, cache Cache) (*VM, error) {
	var errs error
	for _, v := range Readers {
		ok, err := v.Try(rs)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}
		if !ok {
			continue
		}
		vreader, err := v.NewVMReader(rs, cache)
		if err != nil {
			return nil, xerrors.Errorf("open virtual machine error: %w", err)
		}

		return &VM{SectionReader: vreader}, nil
	}
	return nil, xerrors.Errorf("try open virtual machine error: %w", errs)
}
