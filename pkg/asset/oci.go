package asset

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
type Option func(*OCI)

// WithImage takes an OCI v1 Image
func WithImage(img v1.Image) Option {
	return func(a *OCI) {
		a.image = img
	}
}

// OCI is used to download OCI artifacts such as vulnerability database and policies from OCI registries.
type OCI struct {
	m          sync.Mutex
	repository string
	opts       Options

	image v1.Image // For testing
}

// NewOCI returns a new instance of the OCI artifact
func NewOCI(repo string, assetOpts Options, opts ...Option) *OCI {
	art := &OCI{
		repository: repo,
		opts:       assetOpts,
	}

	for _, o := range opts {
		o(art)
	}
	return art
}

func (o *OCI) populate(ctx context.Context) error {
	if o.image != nil {
		return nil
	}

	o.m.Lock()
	defer o.m.Unlock()

	var nameOpts []name.Option
	if o.opts.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	ref, err := name.ParseReference(o.repository, nameOpts...)
	if err != nil {
		return xerrors.Errorf("repository name error (%s): %w", o.repository, err)
	}

	o.image, err = remote.Image(ctx, ref, o.opts.RegistryOptions)
	if err != nil {
		return xerrors.Errorf("OCI repository error: %w", err)
	}
	return nil
}

func (o *OCI) Location() string {
	return o.repository
}

func (o *OCI) Download(ctx context.Context, dir string) error {
	if err := o.populate(ctx); err != nil {
		return err
	}

	layers, err := o.image.Layers()
	if err != nil {
		return xerrors.Errorf("OCI layer error: %w", err)
	}

	manifest, err := o.image.Manifest()
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
	fileName := o.opts.Filename
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
	} else if o.opts.MediaType != "" && o.opts.MediaType != string(layerMediaType) {
		return xerrors.Errorf("unacceptable media type: %s", string(layerMediaType))
	}

	if err = o.download(ctx, layer, fileName, dir, o.opts.Quiet); err != nil {
		return xerrors.Errorf("oci download error: %w", err)
	}

	return nil
}

func (o *OCI) download(ctx context.Context, layer v1.Layer, fileName, dir string, quiet bool) error {
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
	if quiet {
		bar.SetWriter(io.Discard)
	}
	pr := bar.NewProxyReader(rc)
	defer bar.Finish()

	// https://github.com/hashicorp/go-getter/issues/326
	tempDir, err := os.MkdirTemp("", "trivy")
	if err != nil {
		return xerrors.Errorf("failed to create o temp dir: %w", err)
	}

	f, err := os.Create(filepath.Join(tempDir, fileName))
	if err != nil {
		return xerrors.Errorf("failed to create o temp file: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.RemoveAll(tempDir)
	}()

	// Download the layer content into o temporal file
	if _, err = io.Copy(f, pr); err != nil {
		return xerrors.Errorf("copy error: %w", err)
	}

	// Decompress the downloaded file if it is compressed and copy it into the dst
	// NOTE: it's local copying, the insecure option doesn't matter.
	if _, err = downloader.Download(ctx, f.Name(), dir, dir, downloader.Options{}); err != nil {
		return xerrors.Errorf("download error: %w", err)
	}

	return nil
}

func (o *OCI) Digest(ctx context.Context) (string, error) {
	if err := o.populate(ctx); err != nil {
		return "", err
	}

	digest, err := o.image.Digest()
	if err != nil {
		return "", xerrors.Errorf("digest error: %w", err)
	}
	return digest.String(), nil
}
