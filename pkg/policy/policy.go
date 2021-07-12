package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/open-policy-agent/opa/bundle"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
)

const (
	bundleVersion    = 1
	bundleRepository = "ghcr.io/aquasecurity/appshield"
	layerMediaType   = "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"
	updateInterval   = 24 * time.Hour
)

type options struct {
	img   v1.Image
	clock clock.Clock
}

// Option is a functional option
type Option func(*options)

// WithImage takes an OCI v1 Image
func WithImage(img v1.Image) Option {
	return func(opts *options) {
		opts.img = img
	}
}

// WithClock takes a clock
func WithClock(clock clock.Clock) Option {
	return func(opts *options) {
		opts.clock = clock
	}
}

// Metadata holds default policy metadata
type Metadata struct {
	Digest           string
	LastDownloadedAt time.Time
}

// Client implements policy operations
type Client struct {
	img   v1.Image
	clock clock.Clock
}

// NewClient is the factory method for policy client
func NewClient(opts ...Option) (*Client, error) {
	o := &options{
		clock: clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}

	return &Client{
		img:   o.img,
		clock: o.clock,
	}, nil
}

// LoadBuiltinPolicies loads default policies
func (c *Client) LoadBuiltinPolicies() ([]string, error) {
	f, err := os.Open(manifestPath())
	if err != nil {
		return nil, xerrors.Errorf("manifest file open error (%s): %w", manifestPath(), err)
	}

	var manifest bundle.Manifest
	if err = json.NewDecoder(f).Decode(&manifest); err != nil {
		return nil, xerrors.Errorf("json decode error (%s): %w", manifestPath(), err)
	}

	// If the "roots" field is not included in the manifest it defaults to [""]
	// which means that ALL data and policy must come from the bundle.
	if manifest.Roots == nil || len(*manifest.Roots) == 0 {
		return []string{contentDir()}, nil
	}

	var policyPaths []string
	for _, root := range *manifest.Roots {
		policyPaths = append(policyPaths, filepath.Join(contentDir(), root))
	}

	return policyPaths, nil
}

// NeedsUpdate returns if the default policy should be updated
func (c *Client) NeedsUpdate() (bool, error) {
	f, err := os.Open(metadataPath())
	if err != nil {
		log.Logger.Debugf("Failed to open the policy metadata: %s", err)
		return true, nil
	}

	var meta Metadata
	if err = json.NewDecoder(f).Decode(&meta); err != nil {
		log.Logger.Warnf("Policy metadata decode error: %s", err)
		return true, nil
	}

	// No need to update if it's been within a day since the last update.
	if c.clock.Now().Before(meta.LastDownloadedAt.Add(updateInterval)) {
		return false, nil
	}

	if err = c.populateImage(); err != nil {
		return false, xerrors.Errorf("OPA bundle error: %w", err)
	}

	digest, err := c.img.Digest()
	if err != nil {
		return false, xerrors.Errorf("digest error: %w", err)
	}

	if meta.Digest != digest.String() {
		return true, nil
	}

	// Update DownloadedAt with the current time.
	// Otherwise, if there are no updates in the remote registry,
	// the digest will be fetched every time even after this.
	if err = c.updateMetadata(meta.Digest, time.Now()); err != nil {
		return false, xerrors.Errorf("unable to update the policy metadata: %w", err)
	}

	return false, nil

}

func (c *Client) populateImage() error {
	if c.img == nil {
		repo := fmt.Sprintf("%s:%d", bundleRepository, bundleVersion)
		ref, err := name.ParseReference(repo)
		if err != nil {
			return xerrors.Errorf("repository name error (%s): %w", repo, err)
		}

		c.img, err = remote.Image(ref)
		if err != nil {
			return xerrors.Errorf("OCI repository error: %w", err)
		}
	}
	return nil
}

// DownloadBuiltinPolicies download default policies from GitHub Pages
func (c *Client) DownloadBuiltinPolicies(ctx context.Context) error {
	if err := c.populateImage(); err != nil {
		return xerrors.Errorf("OPA bundle error: %w", err)
	}

	layers, err := c.img.Layers()
	if err != nil {
		return xerrors.Errorf("OCI layer error: %w", err)
	}

	if len(layers) != 1 {
		return xerrors.Errorf("OPA bundle must be a single layer: %w", err)
	}

	bundleLayer := layers[0]
	mediaType, err := bundleLayer.MediaType()
	if err != nil {
		return xerrors.Errorf("media type error: %w", err)
	}

	if mediaType != layerMediaType {
		return xerrors.Errorf("unacceptable media type: %s", mediaType)
	}

	if err = c.downloadBuiltinPolicies(ctx, bundleLayer); err != nil {
		return xerrors.Errorf("download error: %w", err)
	}

	digest, err := c.img.Digest()
	if err != nil {
		return xerrors.Errorf("digest error: %w", err)
	}
	log.Logger.Debugf("Digest of the built-in policies: %s", digest)

	// Update metadata.json with the new digest and the current date
	if err = c.updateMetadata(digest.String(), c.clock.Now()); err != nil {
		return xerrors.Errorf("unable to update the policy metadata: %w", err)
	}

	return nil
}

func (c *Client) downloadBuiltinPolicies(ctx context.Context, bundleLayer v1.Layer) error {
	// Take the first layer as OPA bundle
	rc, err := bundleLayer.Compressed()
	if err != nil {
		return xerrors.Errorf("failed to fetch a layer: %w", err)
	}
	defer rc.Close()

	// https://github.com/hashicorp/go-getter/issues/326
	f, err := os.CreateTemp("", "bundle-*.tar.gz")
	if err != nil {
		return xerrors.Errorf("failed to create a temp dir: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}()

	// Download bundle.tar.gz into a temporal file
	if _, err = io.Copy(f, rc); err != nil {
		return xerrors.Errorf("copy error: %w", err)
	}

	// Decompress bundle.tar.gz and copy into the cache dir
	dst := contentDir()
	if err = downloader.Download(ctx, f.Name(), dst, dst); err != nil {
		return xerrors.Errorf("policy download error: %w", err)
	}

	return nil
}

func (c *Client) updateMetadata(digest string, now time.Time) error {
	meta := Metadata{
		Digest:           digest,
		LastDownloadedAt: now,
	}

	f, err := os.Create(metadataPath())
	if err != nil {
		return xerrors.Errorf("failed to open a policy manifest: %w", err)
	}
	defer f.Close()

	if err = json.NewEncoder(f).Encode(meta); err != nil {
		return xerrors.Errorf("json encode error: %w", err)
	}

	return nil
}

func policyDir() string {
	return filepath.Join(utils.CacheDir(), "policy")
}

func contentDir() string {
	return filepath.Join(policyDir(), "content")
}

func metadataPath() string {
	return filepath.Join(policyDir(), "metadata.json")
}

func manifestPath() string {
	return filepath.Join(contentDir(), bundle.ManifestExt)
}
