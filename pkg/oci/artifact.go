package oci

import (
	"context"
	"io"
	"os"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/xerrors"
)

type options struct {
	img v1.Image
}

// Option is a functional option
type Option func(*options)

// WithImage takes an OCI v1 Image
func WithImage(img v1.Image) Option {
	return func(opts *options) {
		opts.img = img
	}
}

// Artifact is used to download artifacts such as vulnerability database and policies from OCI registries.
type Artifact struct {
	image v1.Image
	layer v1.Layer // Take the first layer as OCI artifact
}

// NewArtifact returns a new artifact
func NewArtifact(repo, mediaType string, opts ...Option) (Artifact, error) {
	o := &options{}

	for _, opt := range opts {
		opt(o)
	}

	if o.img == nil {
		ref, err := name.ParseReference(repo)
		if err != nil {
			return Artifact{}, xerrors.Errorf("repository name error (%s): %w", repo, err)
		}

		o.img, err = remote.Image(ref)
		if err != nil {
			return Artifact{}, xerrors.Errorf("OCI repository error: %w", err)
		}
	}

	layers, err := o.img.Layers()
	if err != nil {
		return Artifact{}, xerrors.Errorf("OCI layer error: %w", err)
	}

	// A single layer is only supported now.
	if len(layers) != 1 {
		return Artifact{}, xerrors.Errorf("OCI artifact must be a single layer: %w", err)
	}

	// Take the first layer
	layer := layers[0]

	layerMediaType, err := layer.MediaType()
	if err != nil {
		return Artifact{}, xerrors.Errorf("media type error: %w", err)
	} else if mediaType != string(layerMediaType) {
		return Artifact{}, xerrors.Errorf("unacceptable media type: %s", string(layerMediaType))
	}

	return Artifact{
		image: o.img,
		layer: layer,
	}, nil
}

func (a Artifact) Download(ctx context.Context, dir string) error {
	rc, err := a.layer.Compressed()
	if err != nil {
		return xerrors.Errorf("failed to fetch the layer: %w", err)
	}
	defer rc.Close()

	// https://github.com/hashicorp/go-getter/issues/326
	f, err := os.CreateTemp("", "artifact-*.tar.gz")
	if err != nil {
		return xerrors.Errorf("failed to create a temp file: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()

	// Download the layer content into a temporal file
	if _, err = io.Copy(f, rc); err != nil {
		return xerrors.Errorf("copy error: %w", err)
	}

	// Decompress artifact-xxx.tar.gz and copy it into the cache dir
	if err = downloader.Download(ctx, f.Name(), dir, dir); err != nil {
		return xerrors.Errorf("download error: %w", err)
	}

	return nil
}

func (a Artifact) Digest() (string, error) {
	digest, err := a.image.Digest()
	if err != nil {
		return "", xerrors.Errorf("digest error: %w", err)
	}
	return digest.String(), nil
}
