package oci

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/cheggaaa/pb/v3"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/remote"
	"github.com/aquasecurity/trivy/pkg/version/doc"
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

	// For OCI registries
	types.RegistryOptions

	image v1.Image // For testing
}

// NewArtifact returns a new artifact
func NewArtifact(repo string, registryOpt types.RegistryOptions, opts ...Option) *Artifact {
	art := &Artifact{
		repository:      repo,
		RegistryOptions: registryOpt,
	}

	for _, o := range opts {
		o(art)
	}
	return art
}

func (a *Artifact) populate(ctx context.Context, opt types.RegistryOptions) error {
	if a.image != nil {
		return nil
	}

	a.m.Lock()
	defer a.m.Unlock()

	var nameOpts []name.Option
	if opt.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	ref, err := name.ParseReference(a.repository, nameOpts...)
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
	Quiet     bool
}

func (a *Artifact) Download(ctx context.Context, dir string, opt DownloadOption) error {
	if err := a.populate(ctx, a.RegistryOptions); err != nil {
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

	if err = a.download(ctx, layer, fileName, dir, opt.Quiet); err != nil {
		return xerrors.Errorf("oci download error: %w", err)
	}

	return nil
}

func (a *Artifact) download(ctx context.Context, layer v1.Layer, fileName, dir string, quiet bool) error {
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
	// NOTE: it's local copying, the insecure option doesn't matter.
	if _, err = downloader.Download(ctx, f.Name(), dir, dir, downloader.Options{}); err != nil {
		return xerrors.Errorf("download error: %w", err)
	}

	return nil
}

func (a *Artifact) Digest(ctx context.Context) (string, error) {
	if err := a.populate(ctx, a.RegistryOptions); err != nil {
		return "", err
	}

	digest, err := a.image.Digest()
	if err != nil {
		return "", xerrors.Errorf("digest error: %w", err)
	}
	return digest.String(), nil
}

type Artifacts []*Artifact

// NewArtifacts returns a slice of artifacts.
func NewArtifacts(repos []name.Reference, opt types.RegistryOptions, opts ...Option) Artifacts {
	return lo.Map(repos, func(r name.Reference, _ int) *Artifact {
		return NewArtifact(r.String(), opt, opts...)
	})
}

// Download downloads artifacts until one of them succeeds.
// Attempts to download next artifact if the first one fails due to a temporary error.
func (a Artifacts) Download(ctx context.Context, dst string, opt DownloadOption) error {
	var errs error
	for i, art := range a {
		log.InfoContext(ctx, "Downloading artifact...", log.String("repo", art.repository))
		err := art.Download(ctx, dst, opt)
		if err == nil {
			log.InfoContext(ctx, "Artifact successfully downloaded", log.String("repo", art.repository))
			return nil
		}

		if !shouldTryOtherRepo(err) {
			return xerrors.Errorf("failed to download artifact from %s: %w", art.repository, err)
		}
		log.ErrorContext(ctx, "Failed to download artifact", log.String("repo", art.repository), log.Err(err))
		if i < len(a)-1 {
			log.InfoContext(ctx, "Trying to download artifact from other repository...")
		}
		errs = multierror.Append(errs, err)
	}

	return xerrors.Errorf("failed to download artifact from any source: %w", errs)
}

func shouldTryOtherRepo(err error) bool {
	var terr *transport.Error
	if !errors.As(err, &terr) {
		return false
	}

	for _, diagnostic := range terr.Errors {
		// For better user experience
		if diagnostic.Code == transport.DeniedErrorCode || diagnostic.Code == transport.UnauthorizedErrorCode {
			// e.g. https://aquasecurity.github.io/trivy/latest/docs/references/troubleshooting/#db
			log.Warnf("See %s", doc.URL("/docs/references/troubleshooting/", "db"))
			break
		}
	}

	// try the following artifact if a temporary error occurs
	if terr.Temporary() {
		return true
	}

	// `GCR` periodically returns `BLOB_UNKNOWN` error.
	// cf. https://github.com/aquasecurity/trivy/discussions/8020
	// In this case we need to check other repositories.
	for _, e := range terr.Errors {
		if e.Code == transport.BlobUnknownErrorCode {
			return true
		}
	}

	return false
}
