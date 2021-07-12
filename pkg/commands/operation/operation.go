package operation

import (
	"context"
	"os"
	"strings"

	"github.com/go-redis/redis/v8"
	"github.com/google/wire"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// SuperSet binds cache dependencies
var SuperSet = wire.NewSet(
	cache.NewFSCache,
	wire.Bind(new(cache.LocalArtifactCache), new(cache.FSCache)),
	NewCache,
)

// Cache implements the local cache
type Cache struct {
	cache.Cache
}

// NewCache is the factory method for Cache
func NewCache(backend string) (Cache, error) {
	if strings.HasPrefix(backend, "redis://") {
		log.Logger.Infof("Redis cache: %s", backend)
		options, err := redis.ParseURL(backend)
		if err != nil {
			return Cache{}, err
		}
		redisCache := cache.NewRedisCache(options)
		return Cache{Cache: redisCache}, nil
	}
	fsCache, err := cache.NewFSCache(utils.CacheDir())
	if err != nil {
		return Cache{}, xerrors.Errorf("unable to initialize fs cache: %w", err)
	}
	return Cache{Cache: fsCache}, nil
}

// Reset resets the cache
func (c Cache) Reset() (err error) {
	if err := c.ClearDB(); err != nil {
		return xerrors.Errorf("failed to clear the database: %w", err)
	}
	if err := c.ClearArtifacts(); err != nil {
		return xerrors.Errorf("failed to clear the artifact cache: %w", err)
	}
	return nil
}

// ClearDB clears the DB cache
func (c Cache) ClearDB() (err error) {
	log.Logger.Info("Removing DB file...")
	if err = os.RemoveAll(utils.CacheDir()); err != nil {
		return xerrors.Errorf("failed to remove the directory (%s) : %w", utils.CacheDir(), err)
	}
	return nil
}

// ClearArtifacts clears the artifact cache
func (c Cache) ClearArtifacts() error {
	log.Logger.Info("Removing artifact caches...")
	if err := c.Clear(); err != nil {
		return xerrors.Errorf("failed to remove the cache: %w", err)
	}
	return nil
}

// DownloadDB downloads the DB
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
		if err = client.Download(ctx, cacheDir, light); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
		if err = client.UpdateMetadata(cacheDir); err != nil {
			return xerrors.Errorf("unable to update database metadata: %w", err)
		}
	}

	// for debug
	if err = showDBInfo(cacheDir); err != nil {
		return xerrors.Errorf("failed to show database info: %w", err)
	}
	return nil
}

// InitBuiltinPolicies downloads the built-in policies and loads them
func InitBuiltinPolicies(ctx context.Context, skipUpdate bool) ([]string, error) {
	client, err := policy.NewClient()
	if err != nil {
		return nil, xerrors.Errorf("policy client error: %w", err)
	}

	needsUpdate := false
	if !skipUpdate {
		needsUpdate, err = client.NeedsUpdate()
		if err != nil {
			return nil, xerrors.Errorf("unable to check if built-in policies need to be updated: %w", err)
		}
	}

	if needsUpdate {
		log.Logger.Info("Need to update the built-in policies")
		log.Logger.Info("Downloading the built-in policies...")
		if err = client.DownloadBuiltinPolicies(ctx); err != nil {
			return nil, xerrors.Errorf("failed to download built-in policies: %w", err)
		}
	}

	policyPaths, err := client.LoadBuiltinPolicies()
	if err != nil {
		if skipUpdate {
			log.Logger.Info("No built-in policies were loaded")
			return nil, nil
		}
		return nil, xerrors.Errorf("policy load error: %w", err)
	}
	return policyPaths, nil
}

func showDBInfo(cacheDir string) error {
	m := db.NewMetadata(afero.NewOsFs(), cacheDir)
	metadata, err := m.Get()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Logger.Debugf("DB Schema: %d, Type: %d, UpdatedAt: %s, NextUpdate: %s, DownloadedAt: %s",
		metadata.Version, metadata.Type, metadata.UpdatedAt, metadata.NextUpdate, metadata.DownloadedAt)
	return nil
}
