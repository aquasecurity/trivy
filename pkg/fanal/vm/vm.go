package vm

import (
	"io"
	"io/fs"
	"os"

	// Register
	_ "github.com/aquasecurity/trivy/pkg/fanal/vm/vmdk"

	"github.com/hashicorp/go-multierror"
	"github.com/masahiro331/go-disk"
	"github.com/masahiro331/go-vmdk-parser/pkg/virtualization/vmdk"
	"github.com/masahiro331/go-xfs-filesystem/xfs"
	"golang.org/x/xerrors"
)

var Parsers []VMParser

type VMParser interface {
	Try(rs io.ReadSeeker) (bool, error)
	Open(rs io.ReadSeeker) (*io.SectionReader, error)
}

func RegisterVMParser(parser VMParser) {
	Parsers = append(Parsers, parser)
}

func Parse(f *os.File) (*io.SectionReader, error) {
	return nil, nil
}

func detectVM(f *os.File) (*io.SectionReader, error) {
	var errs error
	ok, err := vmdk.Check(f)
	if err != nil {
		errs = multierror.Append(errs, err)
	}
	f.Seek(0, io.SeekStart)

	if ok {
		reader, err := vmdk.Open(f)
		if err != nil {
			return nil, xerrors.Errorf("failed to open vmdk: %w", err)
		}
		return reader, nil
	}
	// TODO: Support VHD, VHDX, QCOW2

	return nil, multierror.Append(errs, xerrors.New("unsupported virtual machine image"))
}

func DiskWalker() {}

func Open(f *os.File, partitionName string) (fs.FS, error) {
	reader, err := detectVM(f)
	if err != nil {
		return nil, xerrors.Errorf("failed to detect virtual machine type: %w", err)
	}
	f.Seek(0, 0)

	driver, err := disk.NewDriver(reader)
	if err != nil {
		return nil, xerrors.Errorf("failed to new disk driver: %w", err)
	}

	var diskReader io.SectionReader
	for {
		partition, err := driver.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, xerrors.Errorf("failed to next disk error: %w", err)
		}

		if partition.Name() == partitionName && !partition.Bootable() {
			diskReader = partition.GetSectionReader()
			break
		}
	}

	filesystem, err := detectFS(diskReader)
	if err != nil {
		return nil, xerrors.Errorf("failed to detect filesystem error: %w", err)
	}

	return filesystem, nil
}

func detectFS(reader io.SectionReader) (fs.FS, error) {
	ok := xfs.Check(&reader)
	reader.Seek(0, io.SeekStart)

	var errs error
	if ok {
		filesystem, err := xfs.NewFS(reader)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
		return filesystem, err
	}

	return nil, errs
}
