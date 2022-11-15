package vm

import (
	"errors"
	"io"

	"golang.org/x/xerrors"
)

var (
	Readers             []Reader
	ErrInvalidSignature = xerrors.New("invalid signature error")
)

type Reader interface {
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

func New(rs io.ReadSeeker, cache Cache) (*io.SectionReader, error) {
	for _, v := range Readers {
		vreader, err := v.NewVMReader(rs, cache)
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
