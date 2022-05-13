package artifact

import (
	"context"
	"errors"
	"os"

	"github.com/hashicorp/go-multierror"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/analyzer/secret"
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

type ArtifactType string

const (
	containerImageArtifact ArtifactType = "image"
	filesystemArtifact     ArtifactType = "fs"
	rootfsArtifact         ArtifactType = "rootfs"
	repositoryArtifact     ArtifactType = "repo"
	imageArchiveArtifact   ArtifactType = "archive"
)

var (
	defaultPolicyNamespaces = []string{"appshield", "defsec", "builtin"}

	supportedArtifactTypes = []ArtifactType{containerImageArtifact, filesystemArtifact, rootfsArtifact,
		repositoryArtifact, imageArchiveArtifact}

	SkipScan = errors.New("skip subsequent processes")
)

// InitializeScanner defines the initialize function signature of scanner
type InitializeScanner func(context.Context, ScannerConfig) (scanner.Scanner, func(), error)

type ScannerConfig struct {
	// e.g. image name and file path
	Target string

	// Cache
	ArtifactCache      cache.ArtifactCache
	LocalArtifactCache cache.LocalArtifactCache

	// Client/Server options
	RemoteOption client.ScannerOption

	// Artifact options
	ArtifactOption artifact.Option
}

type Runner struct {
	cache  cache.Cache
	dbOpen bool
}

type runnerOption func(*Runner)

// WithCacheClient takes a custom cache implementation
func WithCacheClient(c cache.Cache) runnerOption {
	return func(r *Runner) {
		r.cache = c
	}
}

// NewRunner initializes Runner that provides scanning functionalities.
// It is possible to return SkipScan and it must be handled by caller.
func NewRunner(cliOption Option, opts ...runnerOption) (*Runner, error) {
	r := &Runner{}
	for _, opt := range opts {
		opt(r)
	}

	err := log.InitLogger(cliOption.Debug, cliOption.Quiet)
	if err != nil {
		return nil, xerrors.Errorf("logger error: %w", err)
	}

	if err = r.initCache(cliOption); err != nil {
		return nil, xerrors.Errorf("cache error: %w", err)
	}

	if err = r.initDB(cliOption); err != nil {
		return nil, xerrors.Errorf("DB error: %w", err)
	}

	return r, nil
}

// Close closes everything
func (r *Runner) Close() error {
	var errs error
	if err := r.cache.Close(); err != nil {
		errs = multierror.Append(errs, err)
	}

	if r.dbOpen {
		if err := db.Close(); err != nil {
			errs = multierror.Append(errs, err)
		}
	}
	return errs
}

func (r *Runner) ScanImage(ctx context.Context, opt Option) (types.Report, error) {
	// Disable the lock file scanning
	opt.DisabledAnalyzers = analyzer.TypeLockfiles

	var s InitializeScanner
	switch {
	case opt.Input != "" && opt.RemoteAddr == "":
		// Scan image tarball in standalone mode
		s = archiveStandaloneScanner
	case opt.Input != "" && opt.RemoteAddr != "":
		// Scan image tarball in client/server mode
		s = archiveRemoteScanner
	case opt.Input == "" && opt.RemoteAddr == "":
		// Scan container image in standalone mode
		s = imageStandaloneScanner
	case opt.Input == "" && opt.RemoteAddr != "":
		// Scan container image in client/server mode
		s = imageRemoteScanner
	}

	return r.Scan(ctx, opt, s)
}

func (r *Runner) ScanFilesystem(ctx context.Context, opt Option) (types.Report, error) {
	// Disable the individual package scanning
	opt.DisabledAnalyzers = append(opt.DisabledAnalyzers, analyzer.TypeIndividualPkgs...)

	return r.scanFS(ctx, opt)
}

func (r *Runner) ScanRootfs(ctx context.Context, opt Option) (types.Report, error) {
	// Disable the lock file scanning
	opt.DisabledAnalyzers = append(opt.DisabledAnalyzers, analyzer.TypeLockfiles...)

	return r.scanFS(ctx, opt)
}

func (r *Runner) scanFS(ctx context.Context, opt Option) (types.Report, error) {
	var s InitializeScanner
	if opt.RemoteAddr == "" {
		// Scan filesystem in standalone mode
		s = filesystemStandaloneScanner
	} else {
		// Scan filesystem in client/server mode
		s = filesystemRemoteScanner
	}

	return r.Scan(ctx, opt, s)
}

func (r *Runner) ScanRepository(ctx context.Context, opt Option) (types.Report, error) {
	// Do not scan OS packages
	opt.VulnType = []string{types.VulnTypeLibrary}

	// Disable the OS analyzers and individual package analyzers
	opt.DisabledAnalyzers = append(analyzer.TypeIndividualPkgs, analyzer.TypeOSes...)

	return r.Scan(ctx, opt, repositoryStandaloneScanner)
}

func (r *Runner) Scan(ctx context.Context, opt Option, initializeScanner InitializeScanner) (types.Report, error) {
	report, err := scan(ctx, opt, initializeScanner, r.cache)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan error: %w", err)
	}

	return report, nil
}

func (r *Runner) Filter(ctx context.Context, opt Option, report types.Report) (types.Report, error) {
	resultClient := initializeResultClient()
	results := report.Results
	for i := range results {
		// Fill vulnerability info only in standalone mode
		if opt.RemoteAddr == "" {
			resultClient.FillVulnerabilityInfo(results[i].Vulnerabilities, results[i].Type)
		}
		vulns, misconfSummary, misconfs, secrets, err := resultClient.Filter(ctx, results[i].Vulnerabilities, results[i].Misconfigurations, results[i].Secrets,
			opt.Severities, opt.IgnoreUnfixed, opt.IncludeNonFailures, opt.IgnoreFile, opt.IgnorePolicy)
		if err != nil {
			return types.Report{}, xerrors.Errorf("unable to filter vulnerabilities: %w", err)
		}
		results[i].Vulnerabilities = vulns
		results[i].Misconfigurations = misconfs
		results[i].MisconfSummary = misconfSummary
		results[i].Secrets = secrets
	}
	return report, nil
}

func (r *Runner) Report(opt Option, report types.Report) error {
	if err := pkgReport.Write(report, pkgReport.Option{
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

	return nil
}

func (r *Runner) initDB(c Option) error {
	// When scanning config files or running as client mode, it doesn't need to download the vulnerability database.
	if c.RemoteAddr != "" || !slices.Contains(c.SecurityChecks, types.SecurityCheckVulnerability) {
		return nil
	}

	// download the database file
	noProgress := c.Quiet || c.NoProgress
	if err := operation.DownloadDB(c.AppVersion, c.CacheDir, c.DBRepository, noProgress, c.SkipDBUpdate); err != nil {
		return err
	}

	if c.DownloadDBOnly {
		return SkipScan
	}

	if err := db.Init(c.CacheDir); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	r.dbOpen = true

	return nil
}

func (r *Runner) initCache(c Option) error {
	// Skip initializing cache when custom cache is passed
	if r.cache != nil {
		return nil
	}

	// client/server mode
	if c.RemoteAddr != "" {
		remoteCache := tcache.NewRemoteCache(c.RemoteAddr, c.CustomHeaders, c.Insecure)
		r.cache = tcache.NopCache(remoteCache)
		return nil
	}

	// standalone mode
	utils.SetCacheDir(c.CacheDir)
	cache, err := operation.NewCache(c.CacheOption)
	if err != nil {
		return xerrors.Errorf("unable to initialize the cache: %w", err)
	}
	log.Logger.Debugf("cache dir:  %s", utils.CacheDir())

	if c.Reset {
		defer cache.Close()
		if err = cache.Reset(); err != nil {
			return xerrors.Errorf("cache reset error: %w", err)
		}
		return SkipScan
	}
	if c.ClearCache {
		defer cache.Close()
		if err = cache.ClearArtifacts(); err != nil {
			return xerrors.Errorf("cache clear error: %w", err)
		}
		return SkipScan
	}

	r.cache = cache
	return nil
}

// Run performs artifact scanning
func Run(cliCtx *cli.Context, artifactType ArtifactType) error {
	opt, err := InitOption(cliCtx)
	if err != nil {
		return err
	}

	return run(cliCtx.Context, opt, artifactType)
}

func run(ctx context.Context, opt Option, artifactType ArtifactType) (err error) {
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	defer func() {
		if xerrors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	runner, err := NewRunner(opt)
	if err != nil {
		if errors.Is(err, SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
	}
	defer runner.Close()

	var report types.Report
	switch artifactType {
	case containerImageArtifact, imageArchiveArtifact:
		if report, err = runner.ScanImage(ctx, opt); err != nil {
			return xerrors.Errorf("image scan error: %w", err)
		}
	case filesystemArtifact:
		if report, err = runner.ScanFilesystem(ctx, opt); err != nil {
			return xerrors.Errorf("filesystem scan error: %w", err)
		}
	case rootfsArtifact:
		if report, err = runner.ScanRootfs(ctx, opt); err != nil {
			return xerrors.Errorf("rootfs scan error: %w", err)
		}
	case repositoryArtifact:
		if report, err = runner.ScanRepository(ctx, opt); err != nil {
			return xerrors.Errorf("repository scan error: %w", err)
		}
	}

	report, err = runner.Filter(ctx, opt, report)
	if err != nil {
		return xerrors.Errorf("filter error: %w", err)
	}

	if err = runner.Report(opt, report); err != nil {
		return xerrors.Errorf("report error: %w", err)
	}

	exit(opt, report.Results.Failed())

	return nil
}

func InitOption(ctx *cli.Context) (Option, error) {
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

	// Do not analyze programming language packages when not running in 'library' mode
	if !slices.Contains(opt.VulnType, types.VulnTypeLibrary) {
		analyzers = append(analyzers, analyzer.TypeLanguages...)
	}

	// Do not perform secret scanning when it is not specified.
	if !slices.Contains(opt.SecurityChecks, types.SecurityCheckSecret) {
		analyzers = append(analyzers, analyzer.TypeSecret)
	}

	// Do not perform misconfiguration scanning when it is not specified.
	if !slices.Contains(opt.SecurityChecks, types.SecurityCheckConfig) {
		analyzers = append(analyzers, analyzer.TypeConfigFiles...)
	}

	return analyzers
}

func initScannerConfig(opt Option, cacheClient cache.Cache) (ScannerConfig, types.ScanOptions, error) {
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
		configScannerOptions = config.ScannerOption{
			Trace:        opt.Trace,
			Namespaces:   append(opt.PolicyNamespaces, defaultPolicyNamespaces...),
			PolicyPaths:  opt.PolicyPaths,
			DataPaths:    opt.DataPaths,
			FilePatterns: opt.FilePatterns,
		}
	}

	return ScannerConfig{
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

			// For misconfiguration scanning
			MisconfScannerOption: configScannerOptions,

			// For secret scanning
			SecretScannerOption: secret.ScannerOption{
				ConfigPath: opt.SecretConfigPath,
			},
		},
	}, scanOptions, nil
}

func scan(ctx context.Context, opt Option, initializeScanner InitializeScanner, cacheClient cache.Cache) (
	types.Report, error) {

	scannerConfig, scanOptions, err := initScannerConfig(opt, cacheClient)
	if err != nil {
		return types.Report{}, err
	}

	s, cleanup, err := initializeScanner(ctx, scannerConfig)
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

func exit(c Option, failedResults bool) {
	if c.ExitCode != 0 && failedResults {
		os.Exit(c.ExitCode)
	}
}
