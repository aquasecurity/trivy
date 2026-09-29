package filesystem

import (
	"errors"
	"io"
	"io/fs"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/vm"
)

const cacheSize = 2048

var (
	ErrInvalidHeader = xerrors.New("invalid Header error")
	filesystems      = []Filesystem{
		EXT4{},
		XFS{},
	}
)

type Filesystem interface {
	New(io.SectionReader, vm.Cache[string, any]) (fs.FS, error)
}

func New(sr io.SectionReader) (fs.FS, func(), error) {
	var clean func()

	// Initialize LRU cache for filesystem walking
	lruCache, err := lru.New[string, any](cacheSize)
	if err != nil {
		return nil, clean, xerrors.Errorf("failed to create a LRU cache: %w", err)
	}
	clean = lruCache.Purge

	for _, filesystem := range filesystems {
		// TODO: implement LVM handler
		fsys, err := filesystem.New(sr, lruCache)
		if err != nil {
			if errors.Is(err, ErrInvalidHeader) {
				continue
			}
			return nil, clean, xerrors.Errorf("unexpected fs error: %w", err)
		}
		return fsys, clean, nil
	}
	return nil, clean, xerrors.New("unable to detect filesystem")
}
