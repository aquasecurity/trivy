package db

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/google/wire"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/github"
	"github.com/aquasecurity/trivy/pkg/indicator"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	fullDB  = "trivy.db.gz"
	lightDB = "trivy-light.db.gz"

	metadataFile = "metadata.json"
)

var SuperSet = wire.NewSet(
	// indicator.ProgressBar
	indicator.NewProgressBar,

	// clock.Clock
	wire.Struct(new(clock.RealClock)),
	wire.Bind(new(clock.Clock), new(clock.RealClock)),

	// db.Config
	wire.Struct(new(db.Config)),
	wire.Bind(new(dbOperation), new(db.Config)),

	// github.Client
	github.NewClient,
	wire.Bind(new(github.Operation), new(github.Client)),

	// Metadata
	afero.NewOsFs,
	NewMetadata,

	// db.Client
	NewClient,
	wire.Bind(new(Operation), new(Client)),
)

type Operation interface {
	NeedsUpdate(cliVersion string, skip, light bool) (need bool, err error)
	Download(ctx context.Context, cacheDir string, light bool) (err error)
	UpdateMetadata(cacheDir string) (err error)
}

type dbOperation interface {
	GetMetadata() (metadata db.Metadata, err error)
	StoreMetadata(metadata db.Metadata, dir string) (err error)
}

type Client struct {
	dbc          dbOperation
	githubClient github.Operation
	pb           indicator.ProgressBar
	clock        clock.Clock
	metadata     Metadata
}

func NewClient(dbc dbOperation, githubClient github.Operation, pb indicator.ProgressBar, clock clock.Clock, metadata Metadata) Client {
	return Client{
		dbc:          dbc,
		githubClient: githubClient,
		pb:           pb,
		clock:        clock,
		metadata:     metadata,
	}
}

func (c Client) NeedsUpdate(cliVersion string, light, skip bool) (bool, error) {
	dbType := db.TypeFull
	if light {
		dbType = db.TypeLight
	}

	metadata, err := c.metadata.Get()
	if err != nil {
		log.Logger.Debugf("There is no valid metadata file: %s", err)
		if skip {
			log.Logger.Error("The first run cannot skip downloading DB")
			return false, xerrors.New("--skip-update cannot be specified on the first run")
		}
		metadata = db.Metadata{} // suppress a warning
	}

	if db.SchemaVersion < metadata.Version {
		log.Logger.Errorf("Trivy version (%s) is old. Update to the latest version.", cliVersion)
		return false, xerrors.Errorf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
			metadata.Version, db.SchemaVersion)
	}

	if skip {
		if db.SchemaVersion != metadata.Version {
			log.Logger.Error("The local DB is old and needs to be updated")
			return false, xerrors.New("--skip-update cannot be specified with the old DB")
		} else if metadata.Type != dbType {
			if dbType == db.TypeFull {
				log.Logger.Error("The local DB is a lightweight DB. You have to download a full DB")
			} else {
				log.Logger.Error("The local DB is a full DB. You have to download a lightweight DB")
			}
			return false, xerrors.New("--skip-update cannot be specified with the different schema DB")
		}
		return false, nil
	}

	if db.SchemaVersion == metadata.Version && metadata.Type == dbType &&
		c.clock.Now().Before(metadata.NextUpdate) {
		log.Logger.Debug("DB update was skipped because DB is the latest")
		return false, nil
	}
	return true, nil
}

func (c Client) Download(ctx context.Context, cacheDir string, light bool) error {
	// Remove the metadata file before downloading DB
	if err := c.metadata.Delete(); err != nil {
		log.Logger.Debug("no metadata file")
	}

	dbFile := fullDB
	if light {
		dbFile = lightDB
	}

	rc, size, err := c.githubClient.DownloadDB(ctx, dbFile)
	if err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}
	defer rc.Close()

	bar := c.pb.Start(int64(size))
	barReader := bar.NewProxyReader(rc)
	defer bar.Finish()

	gr, err := gzip.NewReader(barReader)
	if err != nil {
		return xerrors.Errorf("invalid gzip file: %w", err)
	}

	dbPath := db.Path(cacheDir)
	dbDir := filepath.Dir(dbPath)

	if err = os.MkdirAll(dbDir, 0700); err != nil {
		return xerrors.Errorf("failed to mkdir: %w", err)
	}

	file, err := os.Create(dbPath)
	if err != nil {
		return xerrors.Errorf("unable to open DB file: %w", err)
	}
	defer file.Close()

	if _, err = io.Copy(file, gr); err != nil {
		return xerrors.Errorf("failed to save DB file: %w", err)
	}

	return nil
}

func (c Client) UpdateMetadata(cacheDir string) error {
	log.Logger.Debug("Updating database metadata...")

	// make sure the DB has been successfully downloaded
	if err := db.Init(cacheDir); err != nil {
		return xerrors.Errorf("DB error: %w", err)
	}
	defer db.Close()

	metadata, err := c.dbc.GetMetadata()
	if err != nil {
		return xerrors.Errorf("unable to get metadata: %w", err)
	}

	if err = c.dbc.StoreMetadata(metadata, filepath.Join(cacheDir, "db")); err != nil {
		return xerrors.Errorf("failed to store metadata: %w", err)
	}

	return nil
}

type Metadata struct { // TODO: Move all Metadata things to trivy-db repo
	fs       afero.Fs
	filePath string
}

func NewMetadata(fs afero.Fs, cacheDir string) Metadata {
	filePath := MetadataPath(cacheDir)
	return Metadata{
		fs:       fs,
		filePath: filePath,
	}
}

func MetadataPath(cacheDir string) string {
	dbPath := db.Path(cacheDir)
	dbDir := filepath.Dir(dbPath)
	return filepath.Join(dbDir, metadataFile)
}

// DeleteMetadata deletes the file of database metadata
func (m Metadata) Delete() error {
	if err := m.fs.Remove(m.filePath); err != nil {
		return xerrors.Errorf("unable to remove the metadata file: %w", err)
	}
	return nil
}

func (m Metadata) Get() (db.Metadata, error) {
	f, err := m.fs.Open(m.filePath)
	if err != nil {
		return db.Metadata{}, xerrors.Errorf("unable to open a file: %w", err)
	}
	defer f.Close()

	var metadata db.Metadata
	if err = json.NewDecoder(f).Decode(&metadata); err != nil {
		return db.Metadata{}, xerrors.Errorf("unable to decode metadata: %w", err)
	}
	return metadata, nil
}
