package artifact

import (
	"context"
	"errors"
	l "log"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/internal/artifact/config"
	"github.com/aquasecurity/trivy/internal/operation"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

var errEarlyReturn = errors.New("skip subsequent processes")

// InitializeScanner type to define initialize function signature
type InitializeScanner func(context.Context, string, cache.ArtifactCache, cache.LocalArtifactCache, time.Duration,
	[]analyzer.Type) (scanner.Scanner, func(), error)

func run(c config.Config, initializeScanner InitializeScanner) error {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	return runWithContext(ctx, c, initializeScanner)
}

func runWithContext(ctx context.Context, c config.Config, initializeScanner InitializeScanner) error {
	if err := log.InitLogger(c.Debug, c.Quiet); err != nil {
		l.Fatal(err)
	}

	cache, err := initCache(c)
	if errors.Is(err, errEarlyReturn) {
		return nil
	} else if err != nil {
		return err
	}
	defer cache.Close()

	if err = initDB(c); err != nil {
		if errors.Is(err, errEarlyReturn) {
			return nil
		}
		return err
	}
	defer db.Close()

	results, err := scan(ctx, c, initializeScanner, cache)
	if err != nil {
		return err
	}

	results, err = filter(ctx, c, results)
	if err != nil {
		return err
	}

	if err = report.WriteResults(c.Format, c.Output, c.Severities, results, c.Template, c.Light); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(c, results)

	return nil
}

func initCache(c config.Config) (operation.Cache, error) {
	utils.SetCacheDir(c.CacheDir)
	cache, err := operation.NewCache(c.CacheBackend)
	if err != nil {
		return operation.Cache{}, xerrors.Errorf("unable to initialize the cache: %w", err)
	}
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if c.Reset {
		defer cache.Close()
		if err = cache.Reset(); err != nil {
			return operation.Cache{}, xerrors.Errorf("cache reset error: %w", err)
		}
		return operation.Cache{}, errEarlyReturn
	}
	if c.ClearCache {
		defer cache.Close()
		if err = cache.ClearImages(); err != nil {
			return operation.Cache{}, xerrors.Errorf("cache clear error: %w", err)
		}
		return operation.Cache{}, errEarlyReturn
	}
	return cache, nil
}

func initDB(c config.Config) error {
	// download the database file
	noProgress := c.Quiet || c.NoProgress
	if err := operation.DownloadDB(c.AppVersion, c.CacheDir, noProgress, c.Light, c.SkipUpdate); err != nil {
		return err
	}

	if c.DownloadDBOnly {
		return errEarlyReturn
	}

	if err := db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	return nil
}

func scan(ctx context.Context, c config.Config, initializeScanner InitializeScanner, cache cache.Cache) (report.Results, error) {
	target := c.Target
	if c.Input != "" {
		target = c.Input
	}

	scanOptions := types.ScanOptions{
		VulnType:            c.VulnType,
		ScanRemovedPackages: c.ScanRemovedPkgs, // this is valid only for image subcommand
		ListAllPackages:     c.ListAllPkgs,
		SkipFiles:           c.SkipFiles,
		SkipDirectories:     c.SkipDirectories,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	s, cleanup, err := initializeScanner(ctx, target, cache, cache, c.Timeout, disabledAnalyzers)
	if err != nil {
		return nil, xerrors.Errorf("unable to initialize a scanner: %w", err)
	}
	defer cleanup()

	results, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return nil, xerrors.Errorf("error in image scan: %w", err)
	}
	return results, nil
}

func filter(ctx context.Context, c config.Config, results report.Results) (report.Results, error) {
	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, results[i].Type)
		vulns, err := vulnClient.Filter(ctx, results[i].Vulnerabilities,
			c.Severities, c.IgnoreUnfixed, c.IgnoreFile, c.IgnorePolicy)
		if err != nil {
			return nil, xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
		results[i].Vulnerabilities = vulns
	}
	return results, nil
}

func exit(c config.Config, results report.Results) {
	if c.ExitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(c.ExitCode)
			}
		}
	}
}
