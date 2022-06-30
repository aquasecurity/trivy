package artifact

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/hashicorp/go-multierror"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	tcache "github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/secret"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/module"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

// TargetKind represents what kind of artifact Trivy scans
type TargetKind string

const (
	TargetContainerImage TargetKind = "image"
	TargetFilesystem     TargetKind = "fs"
	TargetRootfs         TargetKind = "rootfs"
	TargetRepository     TargetKind = "repo"
	TargetImageArchive   TargetKind = "archive"
	TargetSBOM           TargetKind = "sbom"
)

var (
	defaultPolicyNamespaces = []string{"appshield", "defsec", "builtin"}
	SkipScan                = errors.New("skip subsequent processes")
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

type Runner interface {
	// ScanImage scans an image
	ScanImage(ctx context.Context, opt Option) (types.Report, error)
	// ScanFilesystem scans a filesystem
	ScanFilesystem(ctx context.Context, opt Option) (types.Report, error)
	// ScanRootfs scans rootfs
	ScanRootfs(ctx context.Context, opt Option) (types.Report, error)
	// ScanRepository scans repository
	ScanRepository(ctx context.Context, opt Option) (types.Report, error)
	// ScanSBOM scans SBOM
	ScanSBOM(ctx context.Context, opt Option) (types.Report, error)
	// Filter filter a report
	Filter(ctx context.Context, opt Option, report types.Report) (types.Report, error)
	// Report a writes a report
	Report(opt Option, report types.Report) error
	// Close closes runner
	Close(ctx context.Context) error
}

type runner struct {
	cache  cache.Cache
	dbOpen bool

	// WASM modules
	module *module.Manager
}

type runnerOption func(*runner)

// WithCacheClient takes a custom cache implementation
func WithCacheClient(c cache.Cache) runnerOption {
	return func(r *runner) {
		r.cache = c
	}
}

// NewRunner initializes Runner that provides scanning functionalities.
// It is possible to return SkipScan and it must be handled by caller.
func NewRunner(cliOption Option, opts ...runnerOption) (Runner, error) {
	r := &runner{}
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

	// Initialize WASM modules
	m, err := module.NewManager(cliOption.Context.Context)
	if err != nil {
		return nil, xerrors.Errorf("WASM module error: %w", err)
	}
	m.Register()
	r.module = m

	return r, nil
}

// Close closes everything
func (r *runner) Close(ctx context.Context) error {
	var errs error
	if err := r.cache.Close(); err != nil {
		errs = multierror.Append(errs, err)
	}

	if r.dbOpen {
		if err := db.Close(); err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	if err := r.module.Close(ctx); err != nil {
		errs = multierror.Append(errs, err)
	}
	return errs
}

func (r *runner) ScanImage(ctx context.Context, opt Option) (types.Report, error) {
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

	return r.scanArtifact(ctx, opt, s)
}

func (r *runner) ScanFilesystem(ctx context.Context, opt Option) (types.Report, error) {
	// Disable the individual package scanning
	opt.DisabledAnalyzers = append(opt.DisabledAnalyzers, analyzer.TypeIndividualPkgs...)

	return r.scanFS(ctx, opt)
}

func (r *runner) ScanRootfs(ctx context.Context, opt Option) (types.Report, error) {
	// Disable the lock file scanning
	opt.DisabledAnalyzers = append(opt.DisabledAnalyzers, analyzer.TypeLockfiles...)

	return r.scanFS(ctx, opt)
}

func (r *runner) scanFS(ctx context.Context, opt Option) (types.Report, error) {
	var s InitializeScanner
	if opt.RemoteAddr == "" {
		// Scan filesystem in standalone mode
		s = filesystemStandaloneScanner
	} else {
		// Scan filesystem in client/server mode
		s = filesystemRemoteScanner
	}

	return r.scanArtifact(ctx, opt, s)
}

func (r *runner) ScanRepository(ctx context.Context, opt Option) (types.Report, error) {
	// Do not scan OS packages
	opt.VulnType = []string{types.VulnTypeLibrary}

	// Disable the OS analyzers and individual package analyzers
	opt.DisabledAnalyzers = append(analyzer.TypeIndividualPkgs, analyzer.TypeOSes...)

	return r.scanArtifact(ctx, opt, repositoryStandaloneScanner)
}

func (r *runner) ScanSBOM(ctx context.Context, opt Option) (types.Report, error) {
	// Scan vulnerabilities
	opt.ReportOption.VulnType = []string{types.VulnTypeOS, types.VulnTypeLibrary}
	opt.ReportOption.SecurityChecks = []string{types.SecurityCheckVulnerability}

	var s InitializeScanner
	if opt.RemoteAddr == "" {
		// Scan cycloneDX in standalone mode
		s = sbomStandaloneScanner
	} else {
		// Scan cycloneDX in client/server mode
		s = sbomRemoteScanner
	}

	return r.scanArtifact(ctx, opt, s)
}

func (r *runner) scanArtifact(ctx context.Context, opt Option, initializeScanner InitializeScanner) (types.Report, error) {
	// Update the vulnerability database if needed.
	if err := r.initDB(opt); err != nil {
		return types.Report{}, xerrors.Errorf("DB error: %w", err)
	}

	report, err := scan(ctx, opt, initializeScanner, r.cache)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan error: %w", err)
	}

	return report, nil
}

func (r *runner) Filter(ctx context.Context, opt Option, report types.Report) (types.Report, error) {
	results := report.Results

	// Filter results
	for i := range results {
		vulns, misconfSummary, misconfs, secrets, err := result.Filter(ctx, results[i].Vulnerabilities, results[i].Misconfigurations, results[i].Secrets,
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

func (r *runner) Report(opt Option, report types.Report) error {
	if err := pkgReport.Write(report, pkgReport.Option{
		AppVersion:         opt.GlobalOption.AppVersion,
		Format:             opt.Format,
		Output:             opt.Output,
		Tree:               opt.DependencyTree,
		Severities:         opt.Severities,
		OutputTemplate:     opt.Template,
		IncludeNonFailures: opt.IncludeNonFailures,
		Trace:              opt.Trace,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	return nil
}

func (r *runner) initDB(c Option) error {
	// When scanning config files or running as client mode, it doesn't need to download the vulnerability database.
	if c.RemoteAddr != "" || !slices.Contains(c.SecurityChecks, types.SecurityCheckVulnerability) {
		return nil
	}

	// download the database file
	noProgress := c.Quiet || c.NoProgress
	if err := operation.DownloadDB(c.AppVersion, c.CacheDir, c.DBRepository, noProgress, c.Insecure, c.SkipDBUpdate); err != nil {
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

func (r *runner) initCache(c Option) error {
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
func Run(cliCtx *cli.Context, targetKind TargetKind) error {
	opt, err := InitOption(cliCtx)
	if err != nil {
		return xerrors.Errorf("InitOption: %w", err)
	}

	return run(cliCtx.Context, opt, targetKind)
}

func run(ctx context.Context, opt Option, targetKind TargetKind) (err error) {
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	defer func() {
		if xerrors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	r, err := NewRunner(opt)
	if err != nil {
		if errors.Is(err, SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
	}
	defer r.Close(ctx)

	var report types.Report
	switch targetKind {
	case TargetContainerImage, TargetImageArchive:
		if report, err = r.ScanImage(ctx, opt); err != nil {
			return xerrors.Errorf("image scan error: %w", err)
		}
	case TargetFilesystem:
		if report, err = r.ScanFilesystem(ctx, opt); err != nil {
			return xerrors.Errorf("filesystem scan error: %w", err)
		}
	case TargetRootfs:
		if report, err = r.ScanRootfs(ctx, opt); err != nil {
			return xerrors.Errorf("rootfs scan error: %w", err)
		}
	case TargetRepository:
		if report, err = r.ScanRepository(ctx, opt); err != nil {
			return xerrors.Errorf("repository scan error: %w", err)
		}
	case TargetSBOM:
		if report, err = r.ScanSBOM(ctx, opt); err != nil {
			return xerrors.Errorf("sbom scan error: %w", err)
		}
	}

	report, err = r.Filter(ctx, opt, report)
	if err != nil {
		return xerrors.Errorf("filter error: %w", err)
	}

	if err = r.Report(opt, report); err != nil {
		return xerrors.Errorf("report error: %w", err)
	}

	Exit(opt, report.Results.Failed())

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
		ScanRemovedPackages: opt.ScanRemovedPkgs, // this is valid only for 'image' subcommand
		ListAllPackages:     opt.ListAllPkgs,
	}

	if slices.Contains(opt.SecurityChecks, types.SecurityCheckVulnerability) {
		log.Logger.Info("Vulnerability scanning is enabled")
		log.Logger.Debugf("Vulnerability type:  %s", scanOptions.VulnType)
	}

	// ScannerOption is filled only when config scanning is enabled.
	var configScannerOptions config.ScannerOption
	if slices.Contains(opt.SecurityChecks, types.SecurityCheckConfig) {
		log.Logger.Info("Misconfiguration scanning is enabled")
		configScannerOptions = config.ScannerOption{
			Trace:        opt.Trace,
			Namespaces:   append(opt.PolicyNamespaces, defaultPolicyNamespaces...),
			PolicyPaths:  opt.PolicyPaths,
			DataPaths:    opt.DataPaths,
			FilePatterns: opt.FilePatterns,
		}
	}

	// Do not load config file for secret scanning
	if slices.Contains(opt.SecurityChecks, types.SecurityCheckSecret) {
		ver := fmt.Sprintf("v%s", opt.AppVersion)
		if opt.AppVersion == "dev" {
			ver = opt.AppVersion
		}
		log.Logger.Info("Secret scanning is enabled")
		log.Logger.Info("If your scanning is slow, please try '--security-checks vuln' to disable secret scanning")
		log.Logger.Infof("Please see also https://aquasecurity.github.io/trivy/%s/docs/secret/scanning/#recommendation for faster secret detection", ver)
	} else {
		opt.SecretConfigPath = ""
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

func Exit(c Option, failedResults bool) {
	if c.ExitCode != 0 && failedResults {
		os.Exit(c.ExitCode)
	}
}
