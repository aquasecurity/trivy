package operation

import (
	"context"
	"os"

	"github.com/spf13/afero"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils"
)

var SuperSet = wire.NewSet(
	cache.NewFSCache,
	wire.Bind(new(cache.LocalImageCache), new(cache.FSCache)),
	NewCache,
)

type Cache struct {
	client cache.LocalImageCache
}

func NewCache(client cache.LocalImageCache) Cache {
	return Cache{client: client}
}

func (c Cache) Reset() (err error) {
	if err := c.ClearDB(); err != nil {
		return xerrors.Errorf("failed to clear the database: %w", err)
	}
	if err := c.ClearImages(); err != nil {
		return xerrors.Errorf("failed to clear the image cache: %w", err)
	}
	return nil
}

func (c Cache) ClearDB() (err error) {
	log.Logger.Info("Removing DB file...")
	if err = os.RemoveAll(utils.CacheDir()); err != nil {
		return xerrors.Errorf("failed to remove the directory (%s) : %w", utils.CacheDir(), err)
	}
	return nil
}

func (c Cache) ClearImages() error {
	log.Logger.Info("Removing image caches...")
	if err := c.client.Clear(); err != nil {
		return xerrors.Errorf("failed to remove the cache: %w", err)
	}
	return nil
}

func DownloadDB(appVersion, cacheDir string, quiet, light, skipUpdate bool) error {
	client := initializeDBClient(cacheDir, quiet)
	ctx := context.Background()
	needsUpdate, err := client.NeedsUpdate(appVersion, light, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		log.Logger.Info("Need to update DB")
		log.Logger.Info("Downloading DB...")
		if err := client.Download(ctx, cacheDir, light); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
		if err = client.UpdateMetadata(cacheDir); err != nil {
			return xerrors.Errorf("unable to update database metadata: %w", err)
		}
	}

	// for debug
	if err := showDBInfo(cacheDir); err != nil {
		return xerrors.Errorf("failed to show database info: %w", err)
	}
	return nil
}

func showDBInfo(cacheDir string) error {
	m := db.NewMetadata(afero.NewOsFs(), cacheDir)
	metadata, err := m.Get()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Logger.Debugf("DB Schema: %d, Type: %d, UpdatedAt: %s, NextUpdate: %s",
		metadata.Version, metadata.Type, metadata.UpdatedAt, metadata.NextUpdate)
	return nil
}
