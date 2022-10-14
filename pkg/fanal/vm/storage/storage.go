package storage

import (
	"context"
	"io"
	"os"
	"strings"

	ebsfile "github.com/masahiro331/go-ebs-file"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	EBSPrefix  = "ebs:"
	FilePrefix = "file:"
)

type Storage interface {
	Open(string) (*io.SectionReader, error)
	Close() error
}

type File struct {
	*os.File
	cache ebsfile.Cache
}

func (f *File) Open(filePath string) (*io.SectionReader, error) {
	t := strings.TrimPrefix(filePath, FilePrefix)
	fp, err := os.Open(t)
	if err != nil {
		return nil, err
	}
	f.File = fp

	v, err := vm.New(f.File, f.cache)
	if err != nil {
		log.Logger.Debugf("new virtual machine scan error: %s, treat as raw image.", err.Error())
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		return io.NewSectionReader(f, 0, fi.Size()), nil
	}

	return v.SectionReader, nil
}

func (f *File) Close() error {
	return f.File.Close()
}

func NewFile(cache ebsfile.Cache) *File {
	return &File{
		cache: cache,
	}
}

func NewEBS(option ebsfile.Option, ctx context.Context, cache ebsfile.Cache) *EBS {
	return &EBS{
		option: option,
		ctx:    ctx,
		cache:  cache,
	}
}

type EBS struct {
	option ebsfile.Option
	ctx    context.Context
	cache  ebsfile.Cache
}

func (e *EBS) Open(snapshotID string) (*io.SectionReader, error) {
	t := strings.TrimPrefix(snapshotID, EBSPrefix)
	sr, err := ebsfile.Open(t, e.ctx, e.cache, ebsfile.New(e.option))
	if err != nil {
		return nil, xerrors.Errorf("failed to open EBS file: %w", err)
	}
	return sr, nil
}

func (e *EBS) Close() error {
	return nil
}

func NewStorage(t string, option ebsfile.Option, ctx context.Context, c ebsfile.Cache) (Storage, error) {
	var s Storage
	switch {
	case strings.HasPrefix(t, EBSPrefix):
		s = NewEBS(option, ctx, c)
	case strings.HasPrefix(t, FilePrefix):
		s = NewFile(c)
	default:
		s = NewFile(c)
	}
	return s, nil
}
