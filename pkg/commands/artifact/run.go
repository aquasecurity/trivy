package artifact

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/log"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

const defaultPolicyNamespace = "appshield"

var errSkipScan = errors.New("skip subsequent processes")

// InitializeScanner type to define initialize function signature
type InitializeScanner func(context.Context, string, cache.ArtifactCache, cache.LocalArtifactCache, time.Duration,
	[]analyzer.Type, config.ScannerOption) (scanner.Scanner, func(), error)

// InitCache defines cache initializer
type InitCache func(c Option) (cache.Cache, error)

// Run performs artifact scanning
func Run(ctx context.Context, opt Option, initializeScanner InitializeScanner, initCache InitCache) error {
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	return runWithTimeout(ctx, opt, initializeScanner, initCache)
}

func runWithTimeout(ctx context.Context, opt Option, initializeScanner InitializeScanner, initCache InitCache) error {
	if err := log.InitLogger(opt.Debug, opt.Quiet); err != nil {
		return err
	}

	cacheClient, err := initCache(opt)
	if err != nil {
		if errors.Is(err, errSkipScan) {
			return nil
		}
		return xerrors.Errorf("cache error: %w", err)
	}
	defer cacheClient.Close()

	// When scanning config files, it doesn't need to download the vulnerability database.
	if utils.StringInSlice(types.SecurityCheckVulnerability, opt.SecurityChecks) {
		if err = initDB(opt); err != nil {
			if errors.Is(err, errSkipScan) {
				return nil
			}
			return xerrors.Errorf("DB error: %w", err)
		}
		defer db.Close()
	}

	report, err := scan(ctx, opt, initializeScanner, cacheClient)
	if err != nil {
		return xerrors.Errorf("scan error: %w", err)
	}

	report, err = filter(ctx, opt, report)
	if err != nil {
		return xerrors.Errorf("filter error: %w", err)
	}

	if err = pkgReport.Write(report, pkgReport.Option{
		Format:             opt.Format,
		Output:             opt.Output,
		Severities:         opt.Severities,
		OutputTemplate:     opt.Template,
		Light:              opt.Light,
		IncludeNonFailures: opt.IncludeNonFailures,
		Trace:              opt.Trace,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(opt, report.Results)

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
		if err = cache.ClearArtifacts(); err != nil {
			return operation.Cache{}, xerrors.Errorf("cache clear error: %w", err)
		}
		return operation.Cache{}, errSkipScan
	}
	return cache, nil
}

func initDB(c Option) error {
	// download the database file
	noProgress := c.Quiet || c.NoProgress
	if err := operation.DownloadDB(c.AppVersion, c.CacheDir, noProgress, c.Light, c.SkipDBUpdate); err != nil {
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
	pkgReport.Report, error) {
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
		SkipDirs:            opt.SkipDirs,
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
		builtinPolicyPaths, err := operation.InitBuiltinPolicies(ctx, opt.SkipPolicyUpdate)
		if err != nil {
			return pkgReport.Report{}, xerrors.Errorf("failed to initialize built-in policies: %w", err)
		}

		configScannerOptions = config.ScannerOption{
			Trace:        opt.Trace,
			Namespaces:   append(opt.PolicyNamespaces, defaultPolicyNamespace),
			PolicyPaths:  append(opt.PolicyPaths, builtinPolicyPaths...),
			DataPaths:    opt.DataPaths,
			FilePatterns: opt.FilePatterns,
		}
	}

	s, cleanup, err := initializeScanner(ctx, target, cacheClient, cacheClient, opt.Timeout,
		disabledAnalyzers, configScannerOptions)
	if err != nil {
		return pkgReport.Report{}, xerrors.Errorf("unable to initialize a scanner: %w", err)
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return pkgReport.Report{}, xerrors.Errorf("image scan failed: %w", err)
	}
	return report, nil
}

func filter(ctx context.Context, opt Option, report pkgReport.Report) (pkgReport.Report, error) {
	resultClient := initializeResultClient()
	results := report.Results
	for i := range results {
		resultClient.FillVulnerabilityInfo(results[i].Vulnerabilities, results[i].Type)
		vulns, misconfSummary, misconfs, err := resultClient.Filter(ctx, results[i].Vulnerabilities, results[i].Misconfigurations,
			opt.Severities, opt.IgnoreUnfixed, opt.IncludeNonFailures, opt.IgnoreFile, opt.IgnorePolicy)
		if err != nil {
			return pkgReport.Report{}, xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
		results[i].Vulnerabilities = vulns
		results[i].Misconfigurations = misconfs
		results[i].MisconfSummary = misconfSummary
	}
	return report, nil
}

func exit(c Option, results pkgReport.Results) {
	if c.ExitCode != 0 && results.Failed() {
		os.Exit(c.ExitCode)
	}
}
