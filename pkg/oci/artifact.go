package oci

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cheggaaa/pb/v3"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/remote"
)

const (
	// Artifact types
	CycloneDXArtifactType = "application/vnd.cyclonedx+json"
	SPDXArtifactType      = "application/spdx+json"

	// Media types
	OCIImageManifest = "application/vnd.oci.image.manifest.v1+json"

	// Annotations
	titleAnnotation = "org.opencontainers.image.title"
)

var SupportedSBOMArtifactTypes = []string{
	CycloneDXArtifactType,
	SPDXArtifactType,
}

// Option is a functional option
type Option func(*Artifact)

// WithImage takes an OCI v1 Image
func WithImage(img v1.Image) Option {
	return func(a *Artifact) {
		a.image = img
	}
}

// Artifact is used to download artifacts such as vulnerability database and policies from OCI registries.
type Artifact struct {
	m          sync.Mutex
	repository string
	quiet      bool

	// For OCI registries
	types.RemoteOptions

	image v1.Image // For testing
}

// NewArtifact returns a new artifact
func NewArtifact(repo string, quiet bool, remoteOpt types.RemoteOptions, opts ...Option) (*Artifact, error) {
	art := &Artifact{
		repository:    repo,
		quiet:         quiet,
		RemoteOptions: remoteOpt,
	}

	for _, o := range opts {
		o(art)
	}
	return art, nil
}

func (a *Artifact) populate(ctx context.Context, opt types.RemoteOptions) error {
	if a.image != nil {
		return nil
	}

	a.m.Lock()
	defer a.m.Unlock()

	ref, err := name.ParseReference(a.repository)
	if err != nil {
		return xerrors.Errorf("repository name error (%s): %w", a.repository, err)
	}

	a.image, err = remote.Image(ctx, ref, opt)
	if err != nil {
		return xerrors.Errorf("OCI repository error: %w", err)
	}
	return nil
}

type DownloadOption struct {
	MediaType string // Accept any media type if not specified
	Filename  string // Use the annotation if not specified
}

func (a *Artifact) Download(ctx context.Context, dir string, opt DownloadOption) error {
	if err := a.populate(ctx, a.RemoteOptions); err != nil {
		return err
	}

	layers, err := a.image.Layers()
	if err != nil {
		return xerrors.Errorf("OCI layer error: %w", err)
	}

	manifest, err := a.image.Manifest()
	if err != nil {
		return xerrors.Errorf("OCI manifest error: %w", err)
	}

	// A single layer is only supported now.
	if len(layers) != 1 || len(manifest.Layers) != 1 {
		return xerrors.Errorf("OCI artifact must be a single layer")
	}

	// Take the first layer
	layer := layers[0]

	// Take the file name of the first layer if not specified
	fileName := opt.Filename
	if fileName == "" {
		if v, ok := manifest.Layers[0].Annotations[titleAnnotation]; !ok {
			return xerrors.Errorf("annotation %s is missing", titleAnnotation)
		} else {
			fileName = v
		}
	}

	layerMediaType, err := layer.MediaType()
	if err != nil {
		return xerrors.Errorf("media type error: %w", err)
	} else if opt.MediaType != "" && opt.MediaType != string(layerMediaType) {
		return xerrors.Errorf("unacceptable media type: %s", string(layerMediaType))
	}

	if err = a.download(ctx, layer, fileName, dir); err != nil {
		return xerrors.Errorf("oci download error: %w", err)
	}

	return nil
}

func (a *Artifact) download(ctx context.Context, layer v1.Layer, fileName, dir string) error {
	size, err := layer.Size()
	if err != nil {
		return xerrors.Errorf("size error: %w", err)
	}

	rc, err := layer.Compressed()
	if err != nil {
		return xerrors.Errorf("failed to fetch the layer: %w", err)
	}
	defer rc.Close()

	// Show progress bar
	bar := pb.Full.Start64(size)
	if a.quiet {
		bar.SetWriter(io.Discard)
	}
	pr := bar.NewProxyReader(rc)
	defer bar.Finish()

	// https://github.com/hashicorp/go-getter/issues/326
	tempDir, err := os.MkdirTemp("", "trivy")
	if err != nil {
		return xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	f, err := os.Create(filepath.Join(tempDir, fileName))
	if err != nil {
		return xerrors.Errorf("failed to create a temp file: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.RemoveAll(tempDir)
	}()

	// Download the layer content into a temporal file
	if _, err = io.Copy(f, pr); err != nil {
		return xerrors.Errorf("copy error: %w", err)
	}

	// Decompress the downloaded file if it is compressed and copy it into the dst
	if err = downloader.Download(ctx, f.Name(), dir, dir); err != nil {
		return xerrors.Errorf("download error: %w", err)
	}

	return nil
}

func (a *Artifact) Digest(ctx context.Context) (string, error) {
	if err := a.populate(ctx, a.RemoteOptions); err != nil {
		return "", err
	}

	digest, err := a.image.Digest()
	if err != nil {
		return "", xerrors.Errorf("digest error: %w", err)
	}
	return digest.String(), nil
}
