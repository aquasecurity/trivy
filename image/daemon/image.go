package daemon

import (
	"context"
	"io"
	"os"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	dimage "github.com/docker/docker/api/types/image"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"golang.org/x/xerrors"
)

type Image interface {
	v1.Image
	RepoTags() []string
	RepoDigests() []string
}

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

		img, err := tarball.ImageFromPath(f.Name(), nil)
		if err != nil {
			return nil, xerrors.Errorf("failed to initialize the struct from the temporary file: %w", err)
		}

		return img, nil
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
	history []dimage.HistoryResponseItem
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

	diffIDs, err := img.diffIDs()
	if err != nil {
		return nil, xerrors.Errorf("unable to get diff IDs: %w", err)
	}

	created, err := time.Parse(time.RFC3339Nano, img.inspect.Created)
	if err != nil {
		return nil, xerrors.Errorf("failed parsing created %s: %w", img.inspect.Created, err)
	}

	return &v1.ConfigFile{
		Architecture:  img.inspect.Architecture,
		OS:            img.inspect.Os,
		Author:        img.inspect.Author,
		Created:       v1.Time{Time: created},
		DockerVersion: img.inspect.DockerVersion,
		Config: v1.Config{
			Labels: img.inspect.Config.Labels,
			Env:    img.inspect.Config.Env},
		History: img.configHistory(),
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

func (img *image) RepoTags() []string {
	return img.inspect.RepoTags
}

func (img *image) RepoDigests() []string {
	return img.inspect.RepoDigests
}

func (img *image) configHistory() []v1.History {
	// Fill only required metadata
	var history []v1.History
	for _, h := range img.history {
		history = append(history, v1.History{
			Created: v1.Time{
				Time: time.Unix(h.Created, 0).UTC(),
			},
			CreatedBy:  h.CreatedBy,
			Comment:    h.Comment,
			EmptyLayer: h.Size == 0,
		})
	}
	return history
}

func (img *image) diffIDs() ([]v1.Hash, error) {
	var diffIDs []v1.Hash
	for _, l := range img.inspect.RootFS.Layers {
		h, err := v1.NewHash(l)
		if err != nil {
			return nil, xerrors.Errorf("invalid hash %s: %w", l, err)
		}
		diffIDs = append(diffIDs, h)
	}
	return diffIDs, nil
}
