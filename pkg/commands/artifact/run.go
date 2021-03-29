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
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

var errSkipScan = errors.New("skip subsequent processes")

// InitializeScanner type to define initialize function signature
type InitializeScanner func(context.Context, string, cache.ArtifactCache, cache.LocalArtifactCache, time.Duration,
	[]analyzer.Type) (scanner.Scanner, func(), error)

func run(conf Config, initializeScanner InitializeScanner) error {
	ctx, cancel := context.WithTimeout(context.Background(), conf.Timeout)
	defer cancel()

	return runWithContext(ctx, conf, initializeScanner)
}

func runWithContext(ctx context.Context, conf Config, initializeScanner InitializeScanner) error {
	if err := log.InitLogger(conf.Debug, conf.Quiet); err != nil {
		l.Fatal(err)
	}

	cacheClient, err := initCache(conf)
	if err != nil {
		if errors.Is(err, errSkipScan) {
			return nil
		}
		return xerrors.Errorf("cache error: %w", err)
	}
	defer cacheClient.Close()

	if err = initDB(conf); err != nil {
		if errors.Is(err, errSkipScan) {
			return nil
		}
		return xerrors.Errorf("DB error: %w", err)
	}
	defer db.Close()

	results, err := scan(ctx, conf, initializeScanner, cacheClient)
	if err != nil {
		return xerrors.Errorf("scan error: %w", err)
	}

	results, err = filter(ctx, conf, results)
	if err != nil {
		return xerrors.Errorf("filter error: %w", err)
	}

	if err = report.WriteResults(conf.Format, conf.Output, conf.Severities, results, conf.Template, conf.Light); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(conf, results)

	return nil
}

func initCache(c Config) (operation.Cache, error) {
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
		return operation.Cache{}, errSkipScan
	}
	if c.ClearCache {
		defer cache.Close()
		if err = cache.ClearImages(); err != nil {
			return operation.Cache{}, xerrors.Errorf("cache clear error: %w", err)
		}
		return operation.Cache{}, errSkipScan
	}
	return cache, nil
}

func initDB(c Config) error {
	// download the database file
	noProgress := c.Quiet || c.NoProgress
	if err := operation.DownloadDB(c.AppVersion, c.CacheDir, noProgress, c.Light, c.SkipUpdate); err != nil {
		return err
	}

	if c.DownloadDBOnly {
		return errSkipScan
	}

	if err := db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	return nil
}

func scan(ctx context.Context, conf Config, initializeScanner InitializeScanner, cacheClient cache.Cache) (
	report.Results, error) {
	target := conf.Target
	if conf.Input != "" {
		target = conf.Input
	}

	scanOptions := types.ScanOptions{
		VulnType:            conf.VulnType,
		ScanRemovedPackages: conf.ScanRemovedPkgs, // this is valid only for image subcommand
		ListAllPackages:     conf.ListAllPkgs,
		SkipFiles:           conf.SkipFiles,
		SkipDirs:            conf.SkipDirs,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	// It doesn't analyze apk commands by default.
	disabledAnalyzers := []analyzer.Type{analyzer.TypeApkCommand}
	if conf.ScanRemovedPkgs {
		disabledAnalyzers = []analyzer.Type{}
	}

	s, cleanup, err := initializeScanner(ctx, target, cacheClient, cacheClient, conf.Timeout, disabledAnalyzers)
	if err != nil {
		return nil, xerrors.Errorf("unable to initialize a scanner: %w", err)
	}
	defer cleanup()

	results, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return nil, xerrors.Errorf("image scan failed: %w", err)
	}
	return results, nil
}

func filter(ctx context.Context, conf Config, results report.Results) (report.Results, error) {
	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, results[i].Type)
		vulns, err := vulnClient.Filter(ctx, results[i].Vulnerabilities,
			conf.Severities, conf.IgnoreUnfixed, conf.IgnoreFile, conf.IgnorePolicy)
		if err != nil {
			return nil, xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
		results[i].Vulnerabilities = vulns
	}
	return results, nil
}

func exit(c Config, results report.Results) {
	if c.ExitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(c.ExitCode)
			}
		}
	}
}
