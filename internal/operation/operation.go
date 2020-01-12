package operation

import (
	"context"
	"os"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
)

var SuperSet = wire.NewSet(
	cache.Initialize,
	NewCache,
)

type Cache struct {
	client cache.Cache
}

func NewCache(client cache.Cache) Cache {
	return Cache{client: client}
}

func (c Cache) Reset() (err error) {
	if err := c.ClearDB(); err != nil {
		return err
	}
	if err := c.ClearImages(); err != nil {
		return err
	}
	return nil
}

func (c Cache) ClearDB() (err error) {
	log.Logger.Info("Removing DB file...")
	if err = os.RemoveAll(utils.CacheDir()); err != nil {
		return xerrors.New("failed to remove cache")
	}
	return nil
}

func (c Cache) ClearImages() error {
	log.Logger.Info("Removing image caches...")
	if err := c.client.Clear(); err != nil {
		return xerrors.New("failed to remove image layer cache")
	}
	return nil
}

func DownloadDB(appVersion, cacheDir string, quiet, light, skipUpdate bool) error {
	client := initializeDBClient(quiet)
	ctx := context.Background()
	needsUpdate, err := client.NeedsUpdate(ctx, appVersion, light, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		log.Logger.Info("Need to update DB")
		if err = db.Close(); err != nil {
			return xerrors.Errorf("failed db close: %w", err)
		}
		log.Logger.Info("Downloading DB...")
		if err := client.Download(ctx, cacheDir, light); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}

		log.Logger.Info("Reopening DB...")
		if err = db.Init(cacheDir); err != nil {
			return xerrors.Errorf("failed db close: %w", err)
		}
	}

	// for debug
	if err := showDBInfo(); err != nil {
		return xerrors.Errorf("failed to show database info")
	}
	return nil
}

func showDBInfo() error {
	metadata, err := db.Config{}.GetMetadata()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Logger.Debugf("DB Schema: %d, Type: %d, UpdatedAt: %s, NextUpdate: %s",
		metadata.Version, metadata.Type, metadata.UpdatedAt, metadata.NextUpdate)
	return nil
}
