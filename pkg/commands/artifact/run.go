package artifact

import (
	"context"
	"errors"
	"os"

	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-db/pkg/db"
	tcache "github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/log"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

const defaultPolicyNamespace = "appshield"

var errSkipScan = errors.New("skip subsequent processes")

type scannerConfig struct {
	// e.g. image name and file path
	Target string

	// Cache
	ArtifactCache      cache.ArtifactCache
	LocalArtifactCache cache.LocalArtifactCache

	// Client/Server options
	RemoteOption client.ScannerOption

	// Artifact options
	ArtifactOption artifact.Option

	// Misconfiguration scanning options
	MisconfOption config.ScannerOption
}

// InitializeScanner defines the initialize function signature of scanner
type InitializeScanner func(context.Context, scannerConfig) (scanner.Scanner, func(), error)

// InitCache defines cache initializer
type InitCache func(c Option) (cache.Cache, error)

// Run performs artifact scanning
func Run(ctx context.Context, opt Option, initializeScanner InitializeScanner, initCache InitCache) error {
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	err := runWithTimeout(ctx, opt, initializeScanner, initCache)
	if xerrors.Is(err, context.DeadlineExceeded) {
		log.Logger.Warn("Increase --timeout value")
	}
	return err
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

	// When scanning config files or running as client mode, it doesn't need to download the vulnerability database.
	if opt.RemoteAddr == "" && slices.Contains(opt.SecurityChecks, types.SecurityCheckVulnerability) {
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
		AppVersion:         opt.GlobalOption.AppVersion,
		Format:             opt.Format,
		Output:             opt.Output,
		Severities:         opt.Severities,
		OutputTemplate:     opt.Template,
		IncludeNonFailures: opt.IncludeNonFailures,
		Trace:              opt.Trace,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(opt, report.Results)

	return nil
}

func initCache(c Option) (cache.Cache, error) {
	// client/server mode
	if c.RemoteAddr != "" {
		remoteCache := tcache.NewRemoteCache(c.RemoteAddr, c.CustomHeaders, c.Insecure)
		return tcache.NopCache(remoteCache), nil
	}

	// standalone mode
	utils.SetCacheDir(c.CacheDir)
	cache, err := operation.NewCache(c.CacheOption)
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
	if err := operation.DownloadDB(c.AppVersion, c.CacheDir, c.DBRepository, noProgress, c.SkipDBUpdate); err != nil {
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

func initOption(ctx *cli.Context) (Option, error) {
	opt, err := NewOption(ctx)
	if err != nil {
		return Option{}, xerrors.Errorf("option error: %w", err)
	}

	// initialize options
	if err = opt.Init(); err != nil {
		return Option{}, xerrors.Errorf("option initialize error: %w", err)
	}

	return opt, nil
}

func disabledAnalyzers(opt Option) []analyzer.Type {
	// Specified analyzers to be disabled depending on scanning modes
	// e.g. The 'image' subcommand should disable the lock file scanning.
	analyzers := opt.DisabledAnalyzers

	// It doesn't analyze apk commands by default.
	if !opt.ScanRemovedPkgs {
		analyzers = append(analyzers, analyzer.TypeApkCommand)
	}

	// Don't analyze programming language packages when not running in 'library' mode
	if !slices.Contains(opt.VulnType, types.VulnTypeLibrary) {
		analyzers = append(analyzers, analyzer.TypeLanguages...)
	}

	return analyzers
}

func scan(ctx context.Context, opt Option, initializeScanner InitializeScanner, cacheClient cache.Cache) (
	types.Report, error) {
	target := opt.Target
	if opt.Input != "" {
		target = opt.Input
	}

	scanOptions := types.ScanOptions{
		VulnType:            opt.VulnType,
		SecurityChecks:      opt.SecurityChecks,
		ScanRemovedPackages: opt.ScanRemovedPkgs, // this is valid only for image subcommand
		ListAllPackages:     opt.ListAllPkgs,
	}
	log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)

	// ScannerOption is filled only when config scanning is enabled.
	var configScannerOptions config.ScannerOption
	if slices.Contains(opt.SecurityChecks, types.SecurityCheckConfig) {
		noProgress := opt.Quiet || opt.NoProgress
		builtinPolicyPaths, err := operation.InitBuiltinPolicies(ctx, opt.CacheDir, noProgress, opt.SkipPolicyUpdate)
		if err != nil {
			return types.Report{}, xerrors.Errorf("failed to initialize built-in policies: %w", err)
		}

		configScannerOptions = config.ScannerOption{
			Trace:        opt.Trace,
			Namespaces:   append(opt.PolicyNamespaces, defaultPolicyNamespace),
			PolicyPaths:  append(opt.PolicyPaths, builtinPolicyPaths...),
			DataPaths:    opt.DataPaths,
			FilePatterns: opt.FilePatterns,
		}
	}

	s, cleanup, err := initializeScanner(ctx, scannerConfig{
		Target:             target,
		ArtifactCache:      cacheClient,
		LocalArtifactCache: cacheClient,
		RemoteOption: client.ScannerOption{
			RemoteURL:     opt.RemoteAddr,
			CustomHeaders: opt.CustomHeaders,
			Insecure:      opt.Insecure,
		},
		ArtifactOption: artifact.Option{
			DisabledAnalyzers: disabledAnalyzers(opt),
			SkipFiles:         opt.SkipFiles,
			SkipDirs:          opt.SkipDirs,
			InsecureSkipTLS:   opt.Insecure,
			Offline:           opt.OfflineScan,
			NoProgress:        opt.NoProgress || opt.Quiet,
		},
		MisconfOption: configScannerOptions,
	})
	if err != nil {
		return types.Report{}, xerrors.Errorf("unable to initialize a scanner: %w", err)
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return types.Report{}, xerrors.Errorf("image scan failed: %w", err)
	}
	return report, nil
}

func filter(ctx context.Context, opt Option, report types.Report) (types.Report, error) {
	resultClient := initializeResultClient()
	results := report.Results
	for i := range results {
		// Fill vulnerability info only in standalone mode
		if opt.RemoteAddr == "" {
			resultClient.FillVulnerabilityInfo(results[i].Vulnerabilities, results[i].Type)
		}
		vulns, misconfSummary, misconfs, err := resultClient.Filter(ctx, results[i].Vulnerabilities, results[i].Misconfigurations,
			opt.Severities, opt.IgnoreUnfixed, opt.IncludeNonFailures, opt.IgnoreFile, opt.IgnorePolicy)
		if err != nil {
			return types.Report{}, xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
		results[i].Vulnerabilities = vulns
		results[i].Misconfigurations = misconfs
		results[i].MisconfSummary = misconfSummary
	}
	return report, nil
}

func exit(c Option, results types.Results) {
	if c.ExitCode != 0 && results.Failed() {
		os.Exit(c.ExitCode)
	}
}
