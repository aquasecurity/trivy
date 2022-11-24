package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/vm/disk"

	lru "github.com/hashicorp/golang-lru"
	ebsfile "github.com/masahiro331/go-ebs-file"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	TypeEBS  = "ebs"
	TypeFile = "file"
	TypeVM   = "vm"

	// default block size 512 KB
	// Max cache memory size 64 MB
	storageEBSCacheSize = 128

	// default vmdk block size 64 KB
	// If vm type vmdk max cache memory size 64 MB
	storageFILECacheSize = 1024
)

type Storage struct {
	file   *os.File
	Reader *io.SectionReader
	cache  *lru.Cache
	Type   string
}

func Open(ctx context.Context, target string, ebs ebsfile.EBSAPI) (s *Storage, err error) {
	switch {
	case strings.HasPrefix(target, fmt.Sprintf("%s:", TypeEBS)):
		target = strings.TrimPrefix(target, fmt.Sprintf("%s:", TypeEBS))
		s, err = openEBS(ctx, target, ebs)

	case strings.HasPrefix(target, fmt.Sprintf("%s:", TypeFile)):
		target = strings.TrimPrefix(target, fmt.Sprintf("%s:", TypeFile))
		s, err = openFile(target)

	default:
		s, err = openFile(target)
	}
	if err != nil {
		return nil, xerrors.Errorf("failed to open %s: %w", target, err)
	}

	return s, nil
}

func openFile(filePath string) (*Storage, error) {
	cache, err := lru.New(storageFILECacheSize)
	if err != nil {
		return nil, xerrors.Errorf("failed to create new lru cache: %w", err)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	s := &Storage{
		file:  f,
		cache: cache,
	}
	reader, err := disk.New(f, cache)
	if err != nil {
		if errors.Is(err, vm.ErrUnsupportedType) {
			return nil, err
		}

		log.Logger.Debugf("new virtual machine scan error: %s, treat as raw image.", err.Error())
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		s.Reader = io.NewSectionReader(f, 0, fi.Size())
		s.Type = TypeFile
	} else {
		s.Reader = reader
		s.Type = TypeVM
	}
	return s, nil
}

func openEBS(ctx context.Context, snapshotID string, ebs ebsfile.EBSAPI) (*Storage, error) {
	cache, err := lru.New(storageEBSCacheSize)
	if err != nil {
		return nil, xerrors.Errorf("lru cache error: %w", err)
	}

	sr, err := ebsfile.Open(snapshotID, ctx, cache, ebs)
	if err != nil {
		return nil, xerrors.Errorf("EBS error: %w", err)
	}

	return &Storage{
		Reader: sr,
		cache:  cache,
		Type:   TypeEBS,
	}, nil
}

func (s *Storage) Close() error {
	if s.cache != nil {
		s.cache.Purge()
	}
	if s.file == nil {
		return nil
	}
	return s.file.Close()
}
