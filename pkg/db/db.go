package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	SchemaVersion = db.SchemaVersion
	dbMediaType   = "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip"
)

var (
	// GitHub Container Registry
	DefaultGHCRRepository = fmt.Sprintf("%s:%d", "ghcr.io/aquasecurity/trivy-db", db.SchemaVersion)
	defaultGHCRRepository = lo.Must(name.NewTag(DefaultGHCRRepository))

	// GCR mirror
	DefaultGCRRepository = fmt.Sprintf("%s:%d", "mirror.gcr.io/aquasec/trivy-db", db.SchemaVersion)
	defaultGCRRepository = lo.Must(name.NewTag(DefaultGCRRepository))

	Init  = db.Init
	Close = db.Close
	Path  = db.Path
)

type options struct {
	artifact       *oci.Artifact
	dbRepositories []name.Reference
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
func WithDBRepository(dbRepository []name.Reference) Option {
	return func(opts *options) {
		opts.dbRepositories = dbRepository
	}
}

// Client implements DB operations
type Client struct {
	*options

	dbDir    string
	metadata metadata.Client
	quiet    bool
}

func Dir(cacheDir string) string {
	return filepath.Join(cacheDir, "db")
}

// NewClient is the factory method for DB client
func NewClient(dbDir string, quiet bool, opts ...Option) *Client {
	o := &options{
		dbRepositories: []name.Reference{
			defaultGCRRepository,
			defaultGHCRRepository,
		},
	}

	for _, opt := range opts {
		opt(o)
	}

	return &Client{
		options:  o,
		dbDir:    dbDir,
		metadata: metadata.NewClient(dbDir),
		quiet:    quiet,
	}
}

// NeedsUpdate check is DB needs update
func (c *Client) NeedsUpdate(ctx context.Context, cliVersion string, skip bool) (bool, error) {
	var noRequiredFiles bool
	if _, err := os.Stat(db.Path(c.dbDir)); errors.Is(err, os.ErrNotExist) {
		log.DebugContext(ctx, "There is no db file")
		noRequiredFiles = true
	}
	meta, err := c.metadata.Get()
	if err != nil {
		log.DebugContext(ctx, "There is no valid metadata file", log.Err(err))
		noRequiredFiles = true

		meta = metadata.Metadata{Version: db.SchemaVersion}
	}

	// We can't use the DB if either `trivy.db` or `metadata.json` is missing.
	// In that case, we need to download the DB.
	if noRequiredFiles {
		if skip {
			log.ErrorContext(ctx, "The first run cannot skip downloading DB")
			return false, xerrors.New("--skip-db-update cannot be specified on the first run")
		}
		return true, nil
	}

	// There are 3 cases when DownloadAt field is zero:
	// - metadata file was not created yet. This is the first run of Trivy.
	// - trivy-db was downloaded with `oras`. In this case user can use `--skip-db-update` (like for air-gapped) or re-download trivy-db.
	// - trivy-db was corrupted while copying from tmp directory to cache directory. We should update this trivy-db.
	// We can't detect these cases, so we will show warning for users who use oras + air-gapped.
	if meta.DownloadedAt.IsZero() && !skip {
		log.WarnContext(ctx, "Trivy DB may be corrupted and will be re-downloaded. If you manually downloaded DB - use the `--skip-db-update` flag to skip updating DB.")
		return true, nil
	}

	if db.SchemaVersion < meta.Version {
		log.ErrorContext(ctx, "Trivy version is old. Update to the latest version.", log.String("version", cliVersion))
		return false, xerrors.Errorf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}

	if skip {
		if err = c.validate(meta); err != nil {
			return false, xerrors.Errorf("validate error: %w", err)
		}

		log.DebugContext(ctx, "Skipping DB update...")
		return false, nil
	}

	if db.SchemaVersion != meta.Version {
		log.DebugContext(ctx, "The local DB schema version does not match with supported version schema.",
			log.Int("local_version", meta.Version), log.Int("supported_version", db.SchemaVersion))
		return true, nil
	}

	return !c.isNewDB(ctx, meta), nil
}

func (c *Client) validate(meta metadata.Metadata) error {
	if db.SchemaVersion != meta.Version {
		log.Error("The local DB has an old schema version which is not supported by the current version of Trivy CLI. DB needs to be updated.")
		return xerrors.Errorf("--skip-db-update cannot be specified with the old DB schema. Local DB: %d, Expected: %d",
			meta.Version, db.SchemaVersion)
	}
	return nil
}

func (c *Client) isNewDB(ctx context.Context, meta metadata.Metadata) bool {
	now := clock.Now(ctx)
	if now.Before(meta.NextUpdate) {
		log.Debug("DB update was skipped because the local DB is the latest")
		return true
	}

	if now.Before(meta.DownloadedAt.Add(time.Hour)) {
		log.Debug("DB update was skipped because the local DB was downloaded during the last hour")
		return true
	}
	return false
}

// Download downloads the DB file
func (c *Client) Download(ctx context.Context, dst string, opt types.RegistryOptions) error {
	if err := c.downloadDB(ctx, opt, dst); err != nil {
		return xerrors.Errorf("OCI artifact error: %w", err)
	}

	if err := c.updateDownloadedAt(ctx, dst); err != nil {
		return xerrors.Errorf("failed to update downloaded_at: %w", err)
	}
	return nil
}

func (c *Client) Clear(_ context.Context) error {
	if err := os.RemoveAll(c.dbDir); err != nil {
		return xerrors.Errorf("failed to remove vulnerability database: %w", err)
	}
	return nil
}

func (c *Client) updateDownloadedAt(ctx context.Context, dbDir string) error {
	log.Debug("Updating database metadata...")

	// We have to initialize a metadata client here
	// since the destination may be different from the cache directory.
	client := metadata.NewClient(dbDir)
	meta, err := client.Get()
	if err != nil {
		return xerrors.Errorf("unable to get metadata: %w", err)
	}

	meta.DownloadedAt = clock.Now(ctx).UTC()
	if err = client.Update(meta); err != nil {
		return xerrors.Errorf("failed to update metadata: %w", err)
	}

	return nil
}

func (c *Client) initArtifacts(opt types.RegistryOptions) oci.Artifacts {
	if c.artifact != nil {
		return oci.Artifacts{c.artifact}
	}
	return oci.NewArtifacts(c.dbRepositories, opt)
}

func (c *Client) downloadDB(ctx context.Context, opt types.RegistryOptions, dst string) error {
	log.InfoContext(ctx, "Downloading vulnerability DB...")
	downloadOpt := oci.DownloadOption{
		MediaType: dbMediaType,
		Quiet:     c.quiet,
	}
	if err := c.initArtifacts(opt).Download(ctx, dst, downloadOpt); err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}
	return nil
}

func (c *Client) ShowInfo() error {
	meta, err := c.metadata.Get()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Debug("DB info", log.Int("schema", meta.Version), log.Time("updated_at", meta.UpdatedAt),
		log.Time("next_update", meta.NextUpdate), log.Time("downloaded_at", meta.DownloadedAt))
	return nil
}
