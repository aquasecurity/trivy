// Ported from https://github.com/golang/go/blob/e9c96835971044aa4ace37c7787de231bbde05d9/src/cmd/go/internal/version/exe.go

package binary

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"io/ioutil"
)

// An exe is a generic interface to an OS executable (ELF, Mach-O, PE, XCOFF).
type exe interface {
	// ReadData reads and returns up to size byte starting at virtual address addr.
	ReadData(addr, size uint64) ([]byte, error)

	// DataStart returns the writable data segment start address.
	DataStart() (uint64, uint64)
}

// openExe opens file and returns it as an exe.
func openExe(r io.Reader) (exe, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	br := bytes.NewReader(b)

	data := make([]byte, 16)
	if _, err := io.ReadFull(br, data); err != nil {
		return nil, err
	}
	_, err = br.Seek(0, 0)
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(data, []byte("\x7FELF")) {
		e, err := elf.NewFile(br)
		if err != nil {
			return nil, err
		}
		return &elfExe{e}, nil
	}

	return nil, fmt.Errorf("unrecognized executable format")
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
