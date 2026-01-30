package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/go-version/pkg/part"
	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	BundleVersion    = 2 // Latest released MAJOR version for trivy-checks
	BundleRepository = "mirror.gcr.io/aquasec/trivy-checks"
	policyMediaType  = "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"
	updateInterval   = 24 * time.Hour

	VersionAnnotationKey = "org.opencontainers.image.version"
)

type options struct {
	artifact *oci.Artifact
	clock    clock.Clock
}

// WithOCIArtifact takes an OCI artifact
func WithOCIArtifact(art *oci.Artifact) Option {
	return func(opts *options) {
		opts.artifact = art
	}
}

// WithClock takes a clock
func WithClock(c clock.Clock) Option {
	return func(opts *options) {
		opts.clock = c
	}
}

// Option is a functional option
type Option func(*options)

// Client implements check operations
type Client struct {
	*options
	policyDir       string
	checkBundleRepo string
	quiet           bool
}

// Metadata holds default check metadata
type Metadata struct {
	Digest       string
	DownloadedAt time.Time

	// MajorVersion indicates the major version of the bundle.
	// Used to invalidate cache when the major version increases.
	// Nil for old cache entries. Set to 0 for custom builds.
	MajorVersion *int `json:",omitempty"`

	// CustomBuild is true if the bundle was built manually and did not go
	// through the official build process that enriches the manifest with additional data.
	// For custom builds, MajorVersion is not used for cache invalidation.
	CustomBuild bool `json:",omitempty"`
}

func (m Metadata) String() string {
	return fmt.Sprintf(`Check Bundle:
  Digest: %s
  DownloadedAt: %s
`, m.Digest, m.DownloadedAt.UTC())
}

// NewClient is the factory method for check client
func NewClient(cacheDir string, quiet bool, checkBundleRepo string, opts ...Option) (*Client, error) {
	o := &options{
		clock: clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}

	if checkBundleRepo == "" {
		checkBundleRepo = fmt.Sprintf("%s:%d", BundleRepository, BundleVersion)
	}

	return &Client{
		options:         o,
		policyDir:       filepath.Join(cacheDir, "policy"),
		checkBundleRepo: checkBundleRepo,
		quiet:           quiet,
	}, nil
}

func (c *Client) initOCIArtifact(ctx context.Context, registryOpts types.RegistryOptions) {
	if c.artifact == nil {
		log.DebugContext(ctx, "Initializing OCI checks bundle artifact",
			log.String("repository", c.checkBundleRepo))
		c.artifact = oci.NewArtifact(c.checkBundleRepo, registryOpts)
	}
}

// DownloadBuiltinChecks download default policies from GitHub Pages
func (c *Client) DownloadBuiltinChecks(ctx context.Context, registryOpts types.RegistryOptions) error {
	c.initOCIArtifact(ctx, registryOpts)

	dst := c.contentDir()
	if err := c.artifact.Download(ctx, dst, oci.DownloadOption{
		MediaType: policyMediaType,
		Quiet:     c.quiet,
	},
	); err != nil {
		return xerrors.Errorf("download error: %w", err)
	}

	digest, err := c.artifact.Digest(ctx)
	if err != nil {
		return xerrors.Errorf("digest error: %w", err)
	}

	ver, err := c.getBundleMajorVersion(ctx)
	if err != nil {
		return xerrors.Errorf("get bundle version: %w", err)
	}

	isCustomBundle := ver == 0
	if isCustomBundle {
		log.DebugContext(ctx, "Built-in checks (custom build)",
			log.String("digest", digest))
	} else {
		log.DebugContext(ctx, "Built-in checks",
			log.String("digest", digest), log.Int("major_version", ver))
	}

	// Update metadata.json with the new digest and the current date
	if err = c.updateMetadata(Metadata{
		Digest:       digest,
		DownloadedAt: c.clock.Now(),
		MajorVersion: &ver,
		CustomBuild:  isCustomBundle,
	}); err != nil {
		return xerrors.Errorf("unable to update the check metadata: %w", err)
	}

	return nil
}

// BuiltinChecksPath returns default policies
func (c *Client) BuiltinChecksPath() string {
	return c.contentDir()
}

func (c *Client) getBundleMajorVersion(ctx context.Context) (ver int, err error) {
	manifest, err := c.artifact.Manifest(ctx)
	if err != nil {
		return 0, err
	}

	// No annotations → treat as custom build
	if manifest.Annotations == nil {
		return 0, nil
	}

	v, ok := manifest.Annotations[VersionAnnotationKey]
	if !ok || v == "" {
		return 0, nil
	}

	version, err := semver.Parse(v)
	if err != nil {
		// Invalid version → treat as custom build
		return 0, nil
	}

	majorPart, ok := version.Major().(part.Uint64)
	if !ok {
		// Could not extract major part → treat as custom build
		return 0, nil
	}

	return int(majorPart), nil
}

// NeedsUpdate returns if the default check should be updated
func (c *Client) NeedsUpdate(ctx context.Context, registryOpts types.RegistryOptions) (bool, error) {
	meta, err := c.GetMetadata(ctx)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.DebugContext(ctx, "Cache does not exist, will be created")
		} else {
			log.DebugContext(ctx,
				"Invalidating cache: failed to get metadata", log.Err(err),
			)
		}
		return true, nil
	}

	// For official builds, check the major version for cache invalidation.
	// Custom builds may not have a version annotation, so MajorVersion is ignored.
	// Old cache entries without a version will be invalidated once to enrich metadata.
	if !meta.CustomBuild {

		// Invalidate the old cache if it does not store the version.
		if meta.MajorVersion == nil {
			log.DebugContext(ctx,
				"Invalidating cache: missing major version",
				log.String("digest", meta.Digest),
				log.Time("downloaded_at", meta.DownloadedAt),
			)
			return true, nil
		}

		// Invalidate the old cache if its version does not match.
		if *meta.MajorVersion != BundleVersion {
			log.DebugContext(ctx, "Invalidating cache: version mismatch",
				log.Int("cached_major_version", *meta.MajorVersion),
				log.Int("current_major_version", BundleVersion),
			)
			return true, nil
		}
	}

	// No need to update if it's been within a day since the last update.
	if c.clock.Now().Before(meta.DownloadedAt.Add(updateInterval)) {
		return false, nil
	}

	c.initOCIArtifact(ctx, registryOpts)
	digest, err := c.artifact.Digest(ctx)
	if err != nil {
		return false, xerrors.Errorf("digest error: %w", err)
	}

	if meta.Digest != digest {
		log.DebugContext(ctx, "Invalidating cache: digest mismatch",
			log.String("cached_digest", meta.Digest),
			log.String("current_digest", digest),
		)
		return true, nil
	}

	// Update DownloadedAt with the current time.
	// Otherwise, if there are no updates in the remote registry,
	// the digest will be fetched every time even after this.
	if err = c.updateMetadata(Metadata{
		Digest:       meta.Digest,
		DownloadedAt: c.clock.Now(),
		MajorVersion: meta.MajorVersion,
		CustomBuild:  meta.CustomBuild,
	}); err != nil {
		return false, xerrors.Errorf("unable to update the check metadata: %w", err)
	}

	return false, nil
}

func (c *Client) contentDir() string {
	return filepath.Join(c.policyDir, "content")
}

func (c *Client) metadataPath() string {
	return filepath.Join(c.policyDir, "metadata.json")
}

func (c *Client) updateMetadata(meta Metadata) error {
	f, err := os.Create(c.metadataPath())
	if err != nil {
		return xerrors.Errorf("failed to open checks bundle metadata: %w", err)
	}
	defer f.Close()

	if err = json.NewEncoder(f).Encode(meta); err != nil {
		return xerrors.Errorf("json encode error: %w", err)
	}

	return nil
}

func (c *Client) GetMetadata(ctx context.Context) (*Metadata, error) {
	f, err := os.Open(c.metadataPath())
	if err != nil {
		log.DebugContext(ctx, "Failed to open the check metadata", log.Err(err))
		return nil, err
	}
	defer f.Close()

	var meta Metadata
	if err = json.NewDecoder(f).Decode(&meta); err != nil {
		log.WarnContext(ctx, "Check metadata decode error", log.Err(err))
		return nil, err
	}

	return &meta, nil
}

func (c *Client) Clear() error {
	if err := os.RemoveAll(c.policyDir); err != nil {
		return xerrors.Errorf("failed to remove check bundle: %w", err)
	}
	return nil
}
