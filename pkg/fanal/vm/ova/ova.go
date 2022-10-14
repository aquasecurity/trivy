package ova

import (
	"archive/tar"
	"encoding/xml"
	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/masahiro331/go-vmdk-parser/pkg/virtualization/vmdk"
	"golang.org/x/xerrors"
	"io"
	"path/filepath"
)

func init() {
	vm.RegisterVMReader(&OVA{})
}

type OVA struct {
	envelope Envelope
}

func (o OVA) Try(rs io.ReadSeeker) (bool, error) {
	defer rs.Seek(0, io.SeekStart)
	ok, err := vmdk.Check(rs)
	if err != nil {
		return false, xerrors.Errorf("vmdk check error: %w", err)
	}
	return ok, nil
}

func (o OVA) NewVMReader(rs io.ReadSeeker, cache vm.Cache) (*io.SectionReader, error) {
	reader, err := o.open(rs, cache)
	if err != nil {
		return nil, xerrors.Errorf("failed to open vmdk: %w", err)
	}
	return reader, nil
}

func (o OVA) check(r io.Reader) (bool, error) {
	treader := tar.NewReader(r)
	for {
		header, err := treader.Next()
		if err != nil {
			return false, xerrors.Errorf("read ova tar error: %w", err)
		}
		if filepath.Ext(header.Name) != ".ovf" {
			continue
		}
		if err = xml.NewDecoder(treader).Decode(&o.envelope); err != nil {
			return false, xerrors.Errorf("ovf decode error: %w", err)
		}
		break
	}

	return true, nil
}

func (o OVA) open(rs io.ReadSeeker, cache vm.Cache) (*io.SectionReader, error) {
	treader := tar.NewReader(rs)

	for {
		header, err := treader.Next()
		header.FileInfo()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, xerrors.Errorf("read ova tar error: %w", err)
		}

	}
	return nil, nil
}
