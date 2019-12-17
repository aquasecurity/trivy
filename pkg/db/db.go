package db

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/google/wire"
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
)

var SuperSet = wire.NewSet(
	// indicator.ProgressBar
	indicator.NewProgressBar,

	// clock.Clock
	wire.Struct(new(clock.RealClock)),
	wire.Bind(new(clock.Clock), new(clock.RealClock)),

	// db.Config
	wire.Struct(new(db.Config)),

	// github.Client
	github.NewClient,
	wire.Bind(new(github.Operation), new(github.Client)),

	// db.Client
	NewClient,
	wire.Bind(new(Operation), new(Client)),
)

type Operation interface {
	NeedsUpdate(ctx context.Context, cliVersion string, light, skip bool) (bool, error)
	Download(ctx context.Context, cacheDir string, light bool) error
}

type dbOperation interface {
	GetMetadata() (db.Metadata, error)
}

type Client struct {
	dbc          dbOperation
	githubClient github.Operation
	pb           indicator.ProgressBar
	clock        clock.Clock
}

func NewClient(dbc db.Config, githubClient github.Operation, pb indicator.ProgressBar, clock clock.Clock) Client {
	return Client{
		dbc:          dbc,
		githubClient: githubClient,
		pb:           pb,
		clock:        clock,
	}
}

func (c Client) NeedsUpdate(ctx context.Context, cliVersion string, light, skip bool) (bool, error) {
	dbType := db.TypeFull
	if light {
		dbType = db.TypeLight
	}

	metadata, err := c.dbc.GetMetadata()
	if err != nil {
		log.Logger.Debug("This is the first run")
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

	_, err = io.Copy(file, gr)
	if err != nil {
		return xerrors.Errorf("failed to save DB file: %w", err)
	}
	return nil
}
