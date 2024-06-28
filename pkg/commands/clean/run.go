package clean

import (
	"context"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/policy"
)

func Run(ctx context.Context, opts flag.Options) error {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	if !opts.CleanAll && !opts.CleanScanCache && !opts.CleanVulnerabilityDB && !opts.CleanJavaDB && !opts.CleanChecksBundle {
		return xerrors.New("no clean option is specified")
	}

	if opts.CleanAll {
		return cleanAll(ctx, opts)
	}

	if opts.CleanScanCache {
		if err := cleanScanCache(ctx, opts); err != nil {
			return xerrors.Errorf("failed to remove scan cache : %w", err)
		}
	}

	if opts.CleanVulnerabilityDB {
		if err := cleanVulnerabilityDB(ctx, opts); err != nil {
			return xerrors.Errorf("vuln db clean error: %w", err)
		}
	}

	if opts.CleanJavaDB {
		if err := cleanJavaDB(ctx, opts); err != nil {
			return xerrors.Errorf("java db clean error: %w", err)
		}
	}

	if opts.CleanChecksBundle {
		if err := cleanCheckBundle(opts); err != nil {
			return xerrors.Errorf("check bundle clean error: %w", err)
		}
	}
	return nil
}

func cleanAll(ctx context.Context, opts flag.Options) error {
	log.InfoContext(ctx, "Removing all caches...")
	if err := os.RemoveAll(opts.CacheDir); err != nil {
		return xerrors.Errorf("failed to remove the directory (%s) : %w", opts.CacheDir, err)
	}
	return nil
}

func cleanScanCache(ctx context.Context, opts flag.Options) error {
	log.InfoContext(ctx, "Removing scan cache...")
	c, cleanup, err := cache.New(opts.CacheOpts())
	if err != nil {
		return xerrors.Errorf("failed to instantiate cache client: %w", err)
	}
	defer cleanup()

	if err = c.Clear(); err != nil {
		return xerrors.Errorf("clear scan cache: %w", err)
	}
	return nil
}

func cleanVulnerabilityDB(ctx context.Context, opts flag.Options) error {
	log.InfoContext(ctx, "Removing vulnerability database...")
	if err := db.NewClient(db.Dir(opts.CacheDir), true).Clear(ctx); err != nil {
		return xerrors.Errorf("clear vulnerability database: %w", err)

	}
	return nil
}

func cleanJavaDB(ctx context.Context, opts flag.Options) error {
	log.InfoContext(ctx, "Removing Java database...")
	if err := javadb.Clear(ctx, opts.CacheDir); err != nil {
		return xerrors.Errorf("clear Java database: %w", err)
	}
	return nil
}

func cleanCheckBundle(opts flag.Options) error {
	log.Info("Removing check bundle...")
	c, err := policy.NewClient(opts.CacheDir, true, opts.MisconfOptions.ChecksBundleRepository)
	if err != nil {
		return xerrors.Errorf("failed to instantiate check client: %w", err)
	}
	if err := c.Clear(); err != nil {
		return xerrors.Errorf("clear check bundle: %w", err)
	}
	return nil
}
