// Ported from https://github.com/golang/go/blob/b5a861782312d2b3a4f71e33d9a0c2b01a40fe5f/src/debug/buildinfo/buildinfo.go

package executable

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

var errUnrecognizedFormat = errors.New("unrecognized file format")

// An exe is a generic interface to an OS executable (ELF, Mach-O, PE, XCOFF).
type Exe interface {
	// ReadData reads and returns up to size byte starting at virtual address addr.
	ReadData(addr, size uint64) ([]byte, error)

	// DataStart returns the writable data segment start address.
	DataStart() (uint64, uint64)
}

// openExe opens file and returns it as an exe.
func OpenExe(r io.ReaderAt) (Exe, error) {
	ident := make([]byte, 16)
	if n, err := r.ReadAt(ident, 0); n < len(ident) || err != nil {
		return nil, errUnrecognizedFormat
	}

	switch {
	case bytes.HasPrefix(ident, []byte("\x7FELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return nil, errUnrecognizedFormat
		}
		return &elfExe{f}, nil
	default:
		return nil, errUnrecognizedFormat
	}

	return nil, errUnrecognizedFormat
}

// elfExe is the ELF implementation of the exe interface.
type elfExe struct {
	f *elf.File
}

func (x *elfExe) ReadData(addr, size uint64) ([]byte, error) {
	for _, prog := range x.f.Progs {
		if prog.Vaddr > addr || addr > prog.Vaddr+prog.Filesz-1 {
			continue
		}
		n := prog.Vaddr + prog.Filesz - addr
		if n > size {
			n = size
		}
		data := make([]byte, n)
		_, err := prog.ReadAt(data, int64(addr-prog.Vaddr))
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *elfExe) DataStart() (uint64, uint64) {
	for _, s := range x.f.Sections {
		if s.Name == ".rodata" {
			return s.Addr, s.SectionHeader.Size
		}
	}
	return 0, 0
}
