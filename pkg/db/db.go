package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	dbMediaType         = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
	defaultDBRepository = "ghcr.io/aquasecurity/trivy-db"
)

// Operation defines the DB operations
type Operation interface {
	NeedsUpdate(cliVersion string, skip bool) (need bool, err error)
	Download(ctx context.Context, dst string, opt types.RemoteOptions) (err error)
}

type options struct {
	artifact     *oci.Artifact
	clock        clock.Clock
	dbRepository string
}

// Option is a functional option
type Option func(*options)

// WithOCIArtifact takes an OCI artifact
func WithOCIArtifact(art *oci.Artifact) Option {
	return func(opts *options) {
		opts.artifact = art
	}
}

// WithDBRepository takes a dbRepository
func WithDBRepository(dbRepository string) Option {
	return func(opts *options) {
		opts.dbRepository = dbRepository
	}
}

// WithClock takes a clock
func WithClock(clock clock.Clock) Option {
	return func(opts *options) {
		opts.clock = clock
	}
}

// Client implements DB operations
type Client struct {
	*options

	cacheDir string
	metadata metadata.Client
	quiet    bool
}

// NewClient is the factory method for DB client
func NewClient(cacheDir string, quiet bool, opts ...Option) *Client {
	o := &options{
		clock:        clock.RealClock{},
		dbRepository: defaultDBRepository,
	}

	for _, opt := range opts {
		opt(o)
	}

	return &Client{
		options:  o,
		cacheDir: cacheDir,
		metadata: metadata.NewClient(cacheDir),
		quiet:    quiet,
	}
}

// NeedsUpdate check is DB needs update
func (c *Client) NeedsUpdate(cliVersion string, skip bool) (bool, error) {
	meta, err := c.metadata.Get()
	if err != nil {
		log.Logger.Debugf("There is no valid metadata file: %s", err)
		if skip {
			log.Logger.Error("The first run cannot skip downloading DB")
			return false, xerrors.New("--skip-update cannot be specified on the first run")
		}
		meta = metadata.Metadata{Version: db.SchemaVersion}
	}

	if db.SchemaVersion < meta.Version {
		log.Logger.Errorf("Trivy version (%s) is old. Update to the latest version.", cliVersion)
		return false, xerrors.Errorf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}

	if skip {
		log.Logger.Debug("Skipping DB update...")
		if err = c.validate(meta); err != nil {
			return false, xerrors.Errorf("validate error: %w", err)
		}
		return false, nil
	}

	if db.SchemaVersion != meta.Version {
		log.Logger.Debugf("The local DB schema version (%d) does not match with supported version schema (%d).", meta.Version, db.SchemaVersion)
		return true, nil
	}

	return !c.isNewDB(meta), nil
}

func (c *Client) validate(meta metadata.Metadata) error {
	if db.SchemaVersion != meta.Version {
		log.Logger.Error("The local DB has an old schema version which is not supported by the current version of Trivy CLI. DB needs to be updated.")
		return xerrors.Errorf("--skip-update cannot be specified with the old DB schema. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}
	return nil
}

func (c *Client) isNewDB(meta metadata.Metadata) bool {
	if c.clock.Now().Before(meta.NextUpdate) {
		log.Logger.Debug("DB update was skipped because the local DB is the latest")
		return true
	}

	if c.clock.Now().Before(meta.DownloadedAt.Add(time.Hour)) {
		log.Logger.Debug("DB update was skipped because the local DB was downloaded during the last hour")
		return true
	}
	return false
}

// Download downloads the DB file
func (c *Client) Download(ctx context.Context, dst string, opt types.RemoteOptions) error {
	// Remove the metadata file under the cache directory before downloading DB
	if err := c.metadata.Delete(); err != nil {
		log.Logger.Debug("no metadata file")
	}

	art, err := c.initOCIArtifact(opt)
	if err != nil {
		return xerrors.Errorf("OCI artifact error: %w", err)
	}

	if err = art.Download(ctx, db.Dir(dst), oci.DownloadOption{MediaType: dbMediaType}); err != nil {
		return xerrors.Errorf("database download error: %w", err)
	}

	if err = c.updateDownloadedAt(dst); err != nil {
		return xerrors.Errorf("failed to update downloaded_at: %w", err)
	}
	return nil
}

func (c *Client) updateDownloadedAt(dst string) error {
	log.Logger.Debug("Updating database metadata...")

	// We have to initialize a metadata client here
	// since the destination may be different from the cache directory.
	client := metadata.NewClient(dst)
	meta, err := client.Get()
	if err != nil {
		return xerrors.Errorf("unable to get metadata: %w", err)
	}

	meta.DownloadedAt = c.clock.Now().UTC()
	if err = client.Update(meta); err != nil {
		return xerrors.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

func (c *Client) initOCIArtifact(opt types.RemoteOptions) (*oci.Artifact, error) {
	if c.artifact != nil {
		return c.artifact, nil
	}

	repo := fmt.Sprintf("%s:%d", c.dbRepository, db.SchemaVersion)
	art, err := oci.NewArtifact(repo, c.quiet, opt)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) {
			for _, diagnostic := range terr.Errors {
				// For better user experience
				if diagnostic.Code == transport.DeniedErrorCode || diagnostic.Code == transport.UnauthorizedErrorCode {
					log.Logger.Warn("See https://aquasecurity.github.io/trivy/latest/docs/references/troubleshooting/#db")
					break
				}
			}
		}
		return nil, xerrors.Errorf("OCI artifact error: %w", err)
	}
	return art, nil
}
