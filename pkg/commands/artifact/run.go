package artifact

import (
	"context"
	"errors"
	l "log"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
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
	[]analyzer.Type, config.ScannerOption) (scanner.Scanner, func(), error)

// InitCache defines cache initializer
type InitCache func(c Option) (cache.Cache, error)

// Run performs artifact scanning
func Run(opt Option, initializeScanner InitializeScanner, initCache InitCache) error {
	ctx, cancel := context.WithTimeout(context.Background(), opt.Timeout)
	defer cancel()

	return runWithContext(ctx, opt, initializeScanner, initCache)
}

func runWithContext(ctx context.Context, opt Option, initializeScanner InitializeScanner, initCache InitCache) error {
	if err := log.InitLogger(opt.Debug, opt.Quiet); err != nil {
		l.Fatal(err)
	}

	cacheClient, err := initCache(opt)
	if err != nil {
		if errors.Is(err, errSkipScan) {
			return nil
		}
		return xerrors.Errorf("cache error: %w", err)
	}
	defer cacheClient.Close()

	if err = initDB(opt); err != nil {
		if errors.Is(err, errSkipScan) {
			return nil
		}
		return xerrors.Errorf("DB error: %w", err)
	}
	defer db.Close()

	results, err := scan(ctx, opt, initializeScanner, cacheClient)
	if err != nil {
		return xerrors.Errorf("scan error: %w", err)
	}

	results, err = filter(ctx, opt, results)
	if err != nil {
		return xerrors.Errorf("filter error: %w", err)
	}

	if err = report.WriteResults(opt.Format, opt.Output, opt.Severities, results, opt.Template, opt.Light); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(opt, results)

	return nil
}

func initFSCache(c Option) (cache.Cache, error) {
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

func initDB(c Option) error {
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

func scan(ctx context.Context, opt Option, initializeScanner InitializeScanner, cacheClient cache.Cache) (
	report.Results, error) {
	target := opt.Target
	if opt.Input != "" {
		target = opt.Input
	}

	scanOptions := types.ScanOptions{
		VulnType:            opt.VulnType,
		SecurityChecks:      opt.SecurityChecks,
		ScanRemovedPackages: opt.ScanRemovedPkgs, // this is valid only for image subcommand
		ListAllPackages:     opt.ListAllPkgs,
		SkipFiles:           opt.SkipFiles,
		SkipDirectories:     opt.SkipDirectories,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	// It doesn't analyze apk commands by default.
	disabledAnalyzers := []analyzer.Type{analyzer.TypeApkCommand}
	if opt.ScanRemovedPkgs {
		disabledAnalyzers = []analyzer.Type{}
	}

	// ScannerOptions is filled only when config scanning is enabled.
	var configScannerOptions config.ScannerOption
	if utils.StringInSlice(types.SecurityCheckConfig, opt.SecurityChecks) {
		configScannerOptions = config.ScannerOption{
			PolicyPaths: opt.OPAPolicy,
			DataPaths:   opt.OPAData,
		}
	}

	s, cleanup, err := initializeScanner(ctx, target, cacheClient, cacheClient, opt.Timeout,
		disabledAnalyzers, configScannerOptions)
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

func filter(ctx context.Context, opt Option, results report.Results) (report.Results, error) {
	vulnClient := initializeVulnerabilityClient()
	for i := range results {
		vulnClient.FillInfo(results[i].Vulnerabilities, results[i].Type)
		vulns, err := vulnClient.Filter(ctx, results[i].Vulnerabilities,
			opt.Severities, opt.IgnoreUnfixed, opt.IgnoreFile, opt.IgnorePolicy)
		if err != nil {
			return nil, xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
		results[i].Vulnerabilities = vulns
	}
	return results, nil
}

func exit(c Option, results report.Results) {
	if c.ExitCode != 0 {
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				os.Exit(c.ExitCode)
			}
		}
	}
}
