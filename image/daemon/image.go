package daemon

import (
	"context"
	"io"
	"io/ioutil"
	"os"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/xerrors"
)

var mu sync.Mutex

// image is a wrapper for github.com/google/go-containerregistry/pkg/v1/daemon.Image
// daemon.Image loads the entire image into the memory at first,
// but it doesn't need to load it if the information is already in the cache,
// To avoid entire loading, this wrapper uses ImageInspectWithRaw and checks image ID and layer IDs.
type image struct {
	v1.Image
	opener  opener
	inspect types.ImageInspect
}

type opener func() (v1.Image, error)

// Image implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func Image(ref name.Reference) (v1.Image, *types.ImageInspect, func(), error) {
	cleanup := func() {}

	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, nil, cleanup, xerrors.Errorf("failed to initialize a docker client: %w", err)
	}
	defer func() {
		if err != nil {
			c.Close()
		}
	}()

	inspect, _, err := c.ImageInspectWithRaw(context.Background(), ref.Name())
	if err != nil {
		return nil, nil, cleanup, xerrors.Errorf("unable to inspect the image (%s): %w", ref.Name(), err)
	}

	f, err := ioutil.TempFile("", "fanal-*")
	if err != nil {
		return nil, nil, cleanup, xerrors.Errorf("failed to create a temporary file")
	}

	cleanup = func() {
		c.Close()
		f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(c, ref, f),
		inspect: inspect,
	}, &inspect, cleanup, nil
}

func imageOpener(c *client.Client, ref name.Reference, f *os.File) opener {
	return func() (v1.Image, error) {
		// Store the tarball in local filesystem and return a new reader into the bytes each time we need to access something.
		rc, err := c.ImageSave(context.Background(), []string{ref.Name()})
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
