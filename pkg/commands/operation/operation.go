package operation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"sync"

	"github.com/go-redis/redis/v8"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/wire"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

var mu sync.Mutex

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
func NewCache(c flag.CacheOptions) (Cache, error) {
	if strings.HasPrefix(c.CacheBackend, "redis://") {
		log.Info("Redis cache", log.String("url", c.CacheBackendMasked()))
		options, err := redis.ParseURL(c.CacheBackend)
		if err != nil {
			return Cache{}, err
		}

		if !lo.IsEmpty(c.RedisOptions) {
			caCert, cert, err := GetTLSConfig(c.RedisCACert, c.RedisCert, c.RedisKey)
			if err != nil {
				return Cache{}, err
			}

			options.TLSConfig = &tls.Config{
				RootCAs:      caCert,
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			}
		} else if c.RedisTLS {
			options.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}

		redisCache := cache.NewRedisCache(options, c.CacheTTL)
		return Cache{Cache: redisCache}, nil
	}

	if c.CacheTTL != 0 {
		log.Warn("'--cache-ttl' is only available with Redis cache backend")
	}

	// standalone mode
	fsCache, err := cache.NewFSCache(fsutils.CacheDir())
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
	log.Info("Removing DB file...")
	if err = os.RemoveAll(fsutils.CacheDir()); err != nil {
		return xerrors.Errorf("failed to remove the directory (%s) : %w", fsutils.CacheDir(), err)
	}
	return nil
}

// ClearArtifacts clears the artifact cache
func (c Cache) ClearArtifacts() error {
	log.Info("Removing artifact caches...")
	if err := c.Clear(); err != nil {
		return xerrors.Errorf("failed to remove the cache: %w", err)
	}
	return nil
}

// DownloadDB downloads the DB
func DownloadDB(ctx context.Context, appVersion, cacheDir string, dbRepository name.Reference, quiet, skipUpdate bool,
	opt ftypes.RegistryOptions) error {
	mu.Lock()
	defer mu.Unlock()

	client := db.NewClient(cacheDir, quiet, db.WithDBRepository(dbRepository))
	needsUpdate, err := client.NeedsUpdate(appVersion, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		log.Info("Need to update DB")
		log.Info("Downloading DB...", log.String("repository", dbRepository.String()))
		if err = client.Download(ctx, cacheDir, opt); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
	}

	// for debug
	if err = showDBInfo(cacheDir); err != nil {
		return xerrors.Errorf("failed to show database info: %w", err)
	}
	return nil
}

func showDBInfo(cacheDir string) error {
	m := metadata.NewClient(cacheDir)
	meta, err := m.Get()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Debug("DB info", log.Int("schema", meta.Version), log.Time("updated_at", meta.UpdatedAt),
		log.Time("next_update", meta.NextUpdate), log.Time("downloaded_at", meta.DownloadedAt))
	return nil
}

// InitBuiltinPolicies downloads the built-in policies and loads them
func InitBuiltinPolicies(ctx context.Context, cacheDir string, quiet, skipUpdate bool, checkBundleRepository string, registryOpts ftypes.RegistryOptions) ([]string, error) {
	mu.Lock()
	defer mu.Unlock()

	client, err := policy.NewClient(cacheDir, quiet, checkBundleRepository)
	if err != nil {
		return nil, xerrors.Errorf("check client error: %w", err)
	}

	needsUpdate := false
	if !skipUpdate {
		needsUpdate, err = client.NeedsUpdate(ctx, registryOpts)
		if err != nil {
			return nil, xerrors.Errorf("unable to check if built-in policies need to be updated: %w", err)
		}
	}

	if needsUpdate {
		log.Info("Need to update the built-in policies")
		log.Info("Downloading the built-in policies...")
		if err = client.DownloadBuiltinPolicies(ctx, registryOpts); err != nil {
			return nil, xerrors.Errorf("failed to download built-in policies: %w", err)
		}
	}

	policyPaths, err := client.LoadBuiltinPolicies()
	if err != nil {
		if skipUpdate {
			msg := "No downloadable policies were loaded as --skip-check-update is enabled"
			log.Info(msg)
			return nil, xerrors.Errorf(msg)
		}
		return nil, xerrors.Errorf("check load error: %w", err)
	}
	return policyPaths, nil
}

// GetTLSConfig gets tls config from CA, Cert and Key file
func GetTLSConfig(caCertPath, certPath, keyPath string) (*x509.CertPool, tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, tls.Certificate{}, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	return caCertPool, cert, nil
}

func Exit(opts flag.Options, failedResults bool, m types.Metadata) error {
	if opts.ExitOnEOL != 0 && m.OS != nil && m.OS.Eosl {
		log.Error("Detected EOL OS", log.String("family", string(m.OS.Family)),
			log.String("version", m.OS.Name))
		return &types.ExitError{Code: opts.ExitOnEOL}
	}

	if opts.ExitCode != 0 && failedResults {
		return &types.ExitError{Code: opts.ExitCode}
	}
	return nil
}
