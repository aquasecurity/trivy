package daemon

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/docker/docker/api/types"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/xerrors"
)

var mu sync.Mutex

type opener func() (v1.Image, error)

type imageSave func(context.Context, []string) (io.ReadCloser, error)

func imageOpener(ref string, f *os.File, imageSave imageSave) opener {
	return func() (v1.Image, error) {
		// Store the tarball in local filesystem and return a new reader into the bytes each time we need to access something.
		rc, err := imageSave(context.Background(), []string{ref})
		if err != nil {
			return nil, xerrors.Errorf("unable to export the image: %w", err)
		}
		defer rc.Close()

		if _, err = io.Copy(f, rc); err != nil {
			return nil, xerrors.Errorf("failed to copy the image: %w", err)
		}
		defer f.Close()

		image, err := tarball.ImageFromPath(f.Name(), nil)
		if err != nil {
			return nil, xerrors.Errorf("failed to initialize the struct from the temporary file: %w", err)
		}

		return image, nil
	}
}

// image is a wrapper for github.com/google/go-containerregistry/pkg/v1/daemon.Image
// daemon.Image loads the entire image into the memory at first,
// but it doesn't need to load it if the information is already in the cache,
// To avoid entire loading, this wrapper uses ImageInspectWithRaw and checks image ID and layer IDs.
type image struct {
	v1.Image
	opener  opener
	inspect types.ImageInspect
}

// populateImage initializes an "image" struct.
// This method is called by some goroutines at the same time.
// To prevent multiple heavy initializations, the lock is necessary.
func (img *image) populateImage() (err error) {
	mu.Lock()
	defer mu.Unlock()

	// img.Image is already initialized, so we don't have to do it again.
	if img.Image != nil {
		return nil
	}

	img.Image, err = img.opener()
	if err != nil {
		return xerrors.Errorf("unable to open: %w", err)
	}

	return nil
}

func (img *image) ConfigName() (v1.Hash, error) {
	return v1.NewHash(img.inspect.ID)
}

func (img *image) ConfigFile() (*v1.ConfigFile, error) {
	if len(img.inspect.RootFS.Layers) == 0 {
		// Podman doesn't return RootFS...
		if err := img.populateImage(); err != nil {
			return nil, xerrors.Errorf("unable to populate: %w", err)
		}
		return img.Image.ConfigFile()
	}
	var diffIDs []v1.Hash
	for _, l := range img.inspect.RootFS.Layers {
		h, err := v1.NewHash(l)
		if err != nil {
			return nil, xerrors.Errorf("invalid hash %s: %w", l, err)
		}
		diffIDs = append(diffIDs, h)
	}

	// fill only RootFS in v1.ConfigFile
	return &v1.ConfigFile{
		RootFS: v1.RootFS{
			Type:    img.inspect.RootFS.Type,
			DiffIDs: diffIDs,
		},
	}, nil
}

func (img *image) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	if err := img.populateImage(); err != nil {
		return nil, xerrors.Errorf("unable to populate: %w", err)
	}
	return img.Image.LayerByDiffID(h)
}

func (img *image) RawConfigFile() ([]byte, error) {
	if err := img.populateImage(); err != nil {
		return nil, xerrors.Errorf("unable to populate: %w", err)
	}
	return img.Image.RawConfigFile()
}
