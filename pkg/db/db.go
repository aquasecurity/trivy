package db

import (
	"compress/gzip"
	"context"
	"io"
	"os"

	"k8s.io/utils/clock"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/github"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
)

const (
	fullDB  = "trivy.db.gz"
	lightDB = "trivy-light.db.gz"
)

type Operation interface {
	GetMetadata() (db.Metadata, error)
}

type GitHubOperation interface {
	DownloadDB(ctx context.Context, fileName string) (io.ReadCloser, error)
}

type Client struct {
	dbc          Operation
	clock        clock.Clock
	githubClient GitHubOperation
}

func NewClient(ctx context.Context) Client {
	return Client{
		dbc:          db.Config{},
		clock:        clock.RealClock{},
		githubClient: github.NewClient(ctx),
	}
}

func (c Client) Download(ctx context.Context, cliVersion, cacheDir string, light bool) error {
	dbType := db.TypeFull
	dbFile := fullDB
	message := " Downloading Full DB file..."
	if light {
		dbFile = lightDB
		message = " Downloading Lightweight DB file..."
		dbType = db.TypeLight
	}

	metadata, err := c.dbc.GetMetadata()
	if err != nil {
		log.Logger.Debug("This is the first run")
		metadata = db.Metadata{} // suppress a warning
	}

	if db.SchemaVersion < metadata.Version {
		log.Logger.Errorf("Trivy version (%s) is old. Update to the latest version.", cliVersion)
		return xerrors.Errorf("the version of DB schema doesn't match. Local DB: %d, Expected: %d",
			metadata.Version, db.SchemaVersion)
	}

	if db.SchemaVersion == metadata.Version && metadata.Type == dbType &&
		c.clock.Now().Before(metadata.NextUpdate) {
		log.Logger.Debug("DB update was skipped because DB is the latest")
		return nil
	}

	if err = c.download(ctx, cacheDir, message, dbFile); err != nil {
		return xerrors.Errorf("failed to download the DB file: %w", err)
	}

	log.Logger.Info("Reopen vulnerability DB")
	if err = db.Close(); err != nil {
		return xerrors.Errorf("unable to close old DB: %w", err)
	}
	if err = db.Init(cacheDir); err != nil {
		return xerrors.Errorf("unable to open new DB: %w", err)
	}

	return nil
}

func (c Client) download(ctx context.Context, cacheDir, message, dbFile string) error {
	spinner := utils.NewSpinner(message)
	spinner.Start()
	defer spinner.Stop()

	rc, err := c.githubClient.DownloadDB(ctx, dbFile)
	if err != nil {
		return xerrors.Errorf("failed to download vulnerability DB: %w", err)
	}
	defer rc.Close()

	gr, err := gzip.NewReader(rc)
	if err != nil {
		return xerrors.Errorf("invalid gzip file: %w", err)
	}

	dbPath := db.Path(cacheDir)
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
