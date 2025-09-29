package artifact

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/extension"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/misconf"
	"github.com/aquasecurity/trivy/pkg/module"
	"github.com/aquasecurity/trivy/pkg/notification"
	"github.com/aquasecurity/trivy/pkg/policy"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/doc"
	xhttp "github.com/aquasecurity/trivy/pkg/x/http"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

// TargetKind represents what kind of artifact Trivy scans
type TargetKind string

const (
	TargetContainerImage TargetKind = "image"
	TargetFilesystem     TargetKind = "fs"
	TargetRootfs         TargetKind = "rootfs"
	TargetRepository     TargetKind = "repo"
	TargetSBOM           TargetKind = "sbom"
	TargetVM             TargetKind = "vm"
	TargetK8s            TargetKind = "k8s"
)

var (
	SkipScan = errors.New("skip subsequent processes")
)

// InitializeScanService defines the initialize function signature of scan service
type InitializeScanService func(context.Context, ScannerConfig) (scan.Service, func(), error)

type ScannerConfig struct {
	// e.g. image name and file path
	Target string

	// Cache
	CacheOptions       cache.Options
	RemoteCacheOptions cache.RemoteOptions

	// Client/Server options
	ServerOption client.ServiceOption

	// Artifact options
	ArtifactOption artifact.Option
}

type Runner interface {
	// ScanImage scans an image
	ScanImage(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanFilesystem scans a filesystem
	ScanFilesystem(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanRootfs scans rootfs
	ScanRootfs(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanRepository scans repository
	ScanRepository(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanSBOM scans SBOM
	ScanSBOM(ctx context.Context, opts flag.Options) (types.Report, error)
	// ScanVM scans VM
	ScanVM(ctx context.Context, opts flag.Options) (types.Report, error)
	// Filter filter a report
	Filter(ctx context.Context, opts flag.Options, report types.Report) (types.Report, error)
	// Report a writes a report
	Report(ctx context.Context, opts flag.Options, report types.Report) error
	// Close closes runner
	Close(ctx context.Context) error
}

type runner struct {
	initializeScanService InitializeScanService
	versionChecker        *notification.VersionChecker
	dbOpen                bool

	// WASM modules
	module *module.Manager
}

type RunnerOption func(*runner)

// WithInitializeService takes a custom service initialization function.
// It is useful when Trivy is imported as a library.
func WithInitializeService(f InitializeScanService) RunnerOption {
	return func(r *runner) {
		r.initializeScanService = f
	}
}

// NewRunner initializes Runner that provides scanning functionalities.
// It is possible to return SkipScan and it must be handled by caller.
func NewRunner(ctx context.Context, cliOptions flag.Options, targetKind TargetKind, opts ...RunnerOption) (Runner, error) {
	r := &runner{}
	for _, opt := range opts {
		opt(r)
	}

	// Set the default HTTP transport
	xhttp.SetDefaultTransport(xhttp.NewTransport(xhttp.Options{
		Insecure:  cliOptions.Insecure,
		Timeout:   cliOptions.Timeout,
		TraceHTTP: cliOptions.TraceHTTP,
	}))

	r.versionChecker = notification.NewVersionChecker(string(targetKind), &cliOptions)

	// Update the vulnerability database if needed.
	if err := r.initDB(ctx, cliOptions); err != nil {
		return nil, xerrors.Errorf("DB error: %w", err)
	}

	// Update the VEX repositories if needed
	if err := operation.DownloadVEXRepositories(ctx, cliOptions); err != nil {
		return nil, xerrors.Errorf("VEX repositories download error: %w", err)
	}

	// Initialize WASM modules
	m, err := module.NewManager(ctx, module.Options{
		Dir:            cliOptions.ModuleDir,
		EnabledModules: cliOptions.EnabledModules,
	})
	if err != nil {
		return nil, xerrors.Errorf("WASM module error: %w", err)
	}
	m.Register()
	r.module = m

	// Make a silent attempt to check for updates in the background
	// only do this if the user has not disabled notices or is running
	// in quiet mode
	if r.versionChecker != nil {
		r.versionChecker.RunUpdateCheck(ctx)
	}

	return r, nil
}

// Close closes everything
func (r *runner) Close(ctx context.Context) error {
	var errs error
	if r.dbOpen {
		if err := db.Close(); err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	if err := r.module.Close(ctx); err != nil {
		errs = multierror.Append(errs, err)
	}

	// silently check if there is notifications
	if r.versionChecker != nil {
		r.versionChecker.PrintNotices(ctx, os.Stderr)
	}

	return errs
}

func (r *runner) ScanImage(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable the lock file scanning
	opts.DisabledAnalyzers = analyzer.TypeLockfiles

	var s InitializeScanService
	switch {
	case opts.Input != "" && opts.ServerAddr == "":
		// Scan image tarball in standalone mode
		s = archiveStandaloneScanService
	case opts.Input != "" && opts.ServerAddr != "":
		// Scan image tarball in client/server mode
		s = archiveRemoteScanService
	case opts.Input == "" && opts.ServerAddr == "":
		// Scan container image in standalone mode
		s = imageStandaloneScanService
	case opts.Input == "" && opts.ServerAddr != "":
		// Scan container image in client/server mode
		s = imageRemoteScanService
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanFilesystem(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable scanning of individual package and SBOM files
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeIndividualPkgs...)
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeSBOM)

	return r.scanFS(ctx, opts)
}

func (r *runner) ScanRootfs(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable the lock file scanning
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeLockfiles...)

	return r.scanFS(ctx, opts)
}

func (r *runner) scanFS(ctx context.Context, opts flag.Options) (types.Report, error) {
	var s InitializeScanService
	if opts.ServerAddr == "" {
		// Scan filesystem in standalone mode
		s = filesystemStandaloneScanService
	} else {
		// Scan filesystem in client/server mode
		s = filesystemRemoteScanService
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanRepository(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Do not scan OS packages
	opts.PkgTypes = []string{types.PkgTypeLibrary}

	// Disable the OS analyzers, individual package analyzers and SBOM analyzer
	opts.DisabledAnalyzers = append(analyzer.TypeIndividualPkgs, analyzer.TypeOSes...)
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeSBOM)

	var s InitializeScanService
	if opts.ServerAddr == "" {
		// Scan repository in standalone mode
		s = repositoryStandaloneScanService
	} else {
		// Scan repository in client/server mode
		s = repositoryRemoteScanService
	}
	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanSBOM(ctx context.Context, opts flag.Options) (types.Report, error) {
	var s InitializeScanService
	if opts.ServerAddr == "" {
		// Scan cycloneDX in standalone mode
		s = sbomStandaloneScanService
	} else {
		// Scan cycloneDX in client/server mode
		s = sbomRemoteScanService
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanVM(ctx context.Context, opts flag.Options) (types.Report, error) {
	// TODO: Does VM scan disable lock file..?
	opts.DisabledAnalyzers = analyzer.TypeLockfiles

	var s InitializeScanService
	if opts.ServerAddr == "" {
		// Scan virtual machine in standalone mode
		s = vmStandaloneScanService
	} else {
		// Scan virtual machine in client/server mode
		s = vmRemoteScanService
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) scanArtifact(ctx context.Context, opts flag.Options, initializeService InitializeScanService) (types.Report, error) {
	if r.initializeScanService != nil {
		initializeService = r.initializeScanService
	}
	report, err := r.scan(ctx, opts, initializeService)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan error: %w", err)
	}

	return report, nil
}

func (r *runner) Filter(ctx context.Context, opts flag.Options, report types.Report) (types.Report, error) {
	// Filter results
	if err := result.Filter(ctx, report, opts.FilterOpts()); err != nil {
		return types.Report{}, xerrors.Errorf("filtering error: %w", err)
	}
	return report, nil
}

func (r *runner) Report(ctx context.Context, opts flag.Options, report types.Report) error {
	if err := pkgReport.Write(ctx, report, opts); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}
	return nil
}

func (r *runner) initDB(ctx context.Context, opts flag.Options) error {
	if err := r.initJavaDB(opts); err != nil {
		return err
	}

	// When scanning config files or running as client mode, it doesn't need to download the vulnerability database.
	if opts.ServerAddr != "" || !opts.Scanners.Enabled(types.VulnerabilityScanner) {
		return nil
	}

	// download the database file
	noProgress := opts.Quiet || opts.NoProgress
	if err := operation.DownloadDB(ctx, opts.AppVersion, opts.CacheDir, opts.DBRepositories, noProgress, opts.SkipDBUpdate, opts.RegistryOpts()); err != nil {
		return err
	}

	if opts.DownloadDBOnly {
		return SkipScan
	}

	if err := db.Init(db.Dir(opts.CacheDir)); err != nil {
		return xerrors.Errorf("error in vulnerability DB initialize: %w", err)
	}
	r.dbOpen = true

	return nil
}

func (r *runner) initJavaDB(opts flag.Options) error {
	// When running as server mode, it doesn't need to download the Java database.
	if opts.Listen != "" {
		return nil
	}

	// If vulnerability scanning and SBOM generation are disabled, it doesn't need to download the Java database.
	if !opts.Scanners.Enabled(types.VulnerabilityScanner) &&
		!slices.Contains(types.SupportedSBOMFormats, opts.Format) {
		return nil
	}

	// Update the Java DB
	noProgress := opts.Quiet || opts.NoProgress
	javadb.Init(opts.CacheDir, opts.JavaDBRepositories, opts.SkipJavaDBUpdate, noProgress, opts.RegistryOpts())
	if opts.DownloadJavaDBOnly {
		if err := javadb.Update(); err != nil {
			return xerrors.Errorf("Java DB error: %w", err)
		}
		return SkipScan
	}

	return nil
}

// Run performs artifact scanning
func Run(ctx context.Context, opts flag.Options, targetKind TargetKind) (err error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	if opts.GenerateDefaultConfig {
		log.Info("Writing the default config to trivy-default.yaml...")

		hiddenFlags := flag.HiddenFlags()
		// Viper does not have the ability to remove flags.
		// So we only save the necessary flags and set these flags after viper.Reset
		v := viper.New()
		for _, k := range viper.AllKeys() {
			// Skip the `GenerateDefaultConfigFlag` flags to avoid errors with default config file.
			// Users often use "normal" formats instead of compliance. So we'll skip ComplianceFlag
			// Also don't keep removed or deprecated flags to avoid confusing users.
			if k == flag.GenerateDefaultConfigFlag.ConfigName || k == flag.ComplianceFlag.ConfigName || slices.Contains(hiddenFlags, k) {
				continue
			}
			v.Set(k, viper.Get(k))
		}

		return v.SafeWriteConfigAs("trivy-default.yaml")
	}

	// Call pre-run hooks
	if err := extension.PreRun(ctx, opts); err != nil {
		return xerrors.Errorf("pre run error: %w", err)
	}

	// Run the application
	report, err := run(ctx, opts, targetKind)
	if err != nil {
		return xerrors.Errorf("run error: %w", err)
	}

	// Call post-run hooks
	if err := extension.PostRun(ctx, opts); err != nil {
		return xerrors.Errorf("post run error: %w", err)
	}

	return operation.Exit(opts, report.Results.Failed(), report.Metadata)
}

func run(ctx context.Context, opts flag.Options, targetKind TargetKind) (types.Report, error) {
	// Perform validation checks
	checkOptions(ctx, opts, targetKind)

	r, err := NewRunner(ctx, opts, targetKind)
	if err != nil {
		if errors.Is(err, SkipScan) {
			return types.Report{}, nil
		}
		return types.Report{}, xerrors.Errorf("init error: %w", err)
	}
	defer r.Close(ctx)

	scans := map[TargetKind]func(context.Context, flag.Options) (types.Report, error){
		TargetContainerImage: r.ScanImage,
		TargetFilesystem:     r.ScanFilesystem,
		TargetRootfs:         r.ScanRootfs,
		TargetRepository:     r.ScanRepository,
		TargetSBOM:           r.ScanSBOM,
		TargetVM:             r.ScanVM,
	}

	scanFunction, exists := scans[targetKind]
	if !exists {
		return types.Report{}, xerrors.Errorf("unknown target kind: %s", targetKind)
	}

	// 1. Scan the artifact
	report, err := scanFunction(ctx, opts)
	if err != nil {
		return types.Report{}, xerrors.Errorf("%s scan error: %w", targetKind, err)
	}

	// 2. Filter the results
	report, err = r.Filter(ctx, opts, report)
	if err != nil {
		return types.Report{}, xerrors.Errorf("filter error: %w", err)
	}

	// 3. Report the results
	if err = r.Report(ctx, opts, report); err != nil {
		return types.Report{}, xerrors.Errorf("report error: %w", err)
	}

	return report, nil
}

// checkOptions performs various checks on scan options and shows warnings
func checkOptions(ctx context.Context, opts flag.Options, targetKind TargetKind) {
	// Check client/server mode with misconfiguration and secret scanning
	if opts.ServerAddr != "" && opts.Scanners.AnyEnabled(types.MisconfigScanner, types.SecretScanner) {
		log.WarnContext(ctx,
			fmt.Sprintf(
				"Trivy runs in client/server mode, but misconfiguration and license scanning will be done on the client side, see %s",
				doc.URL("/docs/references/modes/client-server", ""),
			),
		)
	}

	// Check SBOM to SBOM scanning with package filtering flags
	// For SBOM-to-SBOM scanning (for example, to add vulnerabilities to the SBOM file), we should not modify the scanned file.
	// cf. https://github.com/aquasecurity/trivy/pull/9439#issuecomment-3295533665
	if targetKind == TargetSBOM && slices.Contains(types.SupportedSBOMFormats, opts.Format) &&
		(!slices.Equal(opts.PkgTypes, types.PkgTypes) || !slices.Equal(opts.PkgRelationships, ftypes.Relationships)) {
		log.Warn("'--pkg-types' and '--pkg-relationships' options will be ignored when scanning SBOM and outputting SBOM format.")
	}
}

func disabledAnalyzers(opts flag.Options) []analyzer.Type {
	// Specified analyzers to be disabled depending on scanning modes
	// e.g. The 'image' subcommand should disable the lock file scanning.
	analyzers := opts.DisabledAnalyzers
	// It doesn't analyze apk commands by default.
	if !opts.ScanRemovedPkgs {
		analyzers = append(analyzers, analyzer.TypeApkCommand)
	}

	// Do not analyze programming language packages when not running in 'library'
	if !slices.Contains(opts.PkgTypes, types.PkgTypeLibrary) {
		analyzers = append(analyzers, analyzer.TypeLanguages...)
	}

	// Do not perform secret scanning when it is not specified.
	if !opts.Scanners.Enabled(types.SecretScanner) {
		analyzers = append(analyzers, analyzer.TypeSecret)
	}

	// Do not perform misconfiguration scanning when it is not specified.
	if !opts.Scanners.AnyEnabled(types.MisconfigScanner, types.RBACScanner) {
		analyzers = append(analyzers, analyzer.TypeConfigFiles...)
	} else {
		// Filter only enabled misconfiguration scanners
		ma := disabledMisconfigAnalyzers(opts.MisconfigScanners)
		analyzers = append(analyzers, ma...)

		log.Debug("Enabling misconfiguration scanners",
			log.Any("scanners", lo.Without(analyzer.TypeConfigFiles, ma...)))
	}

	// Scanning file headers and license files is expensive.
	// It is performed only when '--scanners license' and '--license-full' are specified together.
	if !opts.Scanners.Enabled(types.LicenseScanner) || !opts.LicenseFull {
		analyzers = append(analyzers, analyzer.TypeLicenseFile)
	}

	// Parsing jar files requires Java-db client
	// But we don't create client if vulnerability analysis is disabled and SBOM format is not used
	// We need to disable jar analyzer to avoid errors
	// TODO disable all languages that don't contain license information for this case
	if !opts.Scanners.Enabled(types.VulnerabilityScanner) && !slices.Contains(types.SupportedSBOMFormats, opts.Format) {
		analyzers = append(analyzers, analyzer.TypeJar)
	}

	// Do not perform misconfiguration scanning on container image config
	// when it is not specified.
	if !opts.ImageConfigScanners.Enabled(types.MisconfigScanner) {
		analyzers = append(analyzers, analyzer.TypeHistoryDockerfile)
	}

	// Skip executable file analysis if Rekor isn't a specified SBOM source.
	if !slices.Contains(opts.SBOMSources, types.SBOMSourceRekor) {
		analyzers = append(analyzers, analyzer.TypeExecutable)
	}

	// Disable RPM archive analyzer unless the environment variable is set
	// TODO: add '--enable-analyzers' and delete this environment variable
	if os.Getenv("TRIVY_EXPERIMENTAL_RPM_ARCHIVE") == "" {
		analyzers = append(analyzers, analyzer.TypeRpmArchive)
	}

	return analyzers
}

func disabledMisconfigAnalyzers(included []analyzer.Type) []analyzer.Type {
	_, missing := lo.Difference(analyzer.TypeConfigFiles, included)
	if len(missing) > 0 {
		log.Error(
			"Invalid misconfiguration scanners provided, using default scanners",
			log.Any("invalid_scanners", missing), log.Any("default_scanners", analyzer.TypeConfigFiles),
		)
		return nil
	}

	return lo.Without(analyzer.TypeConfigFiles, included...)
}

func (r *runner) initScannerConfig(ctx context.Context, opts flag.Options) (ScannerConfig, types.ScanOptions, error) {
	target := opts.Target
	if opts.Input != "" {
		target = opts.Input
	}

	scanOptions := opts.ScanOpts()

	if len(opts.ImageConfigScanners) != 0 {
		log.WithPrefix(log.PrefixContainerImage).Info("Container image config scanners", log.Any("scanners", opts.ImageConfigScanners))
	}

	if opts.Scanners.Enabled(types.SBOMScanner) {
		logger := log.WithPrefix(log.PrefixPackage)
		logger.Debug("Package types", log.Any("types", scanOptions.PkgTypes))
		logger.Debug("Package relationships", log.Any("relationships", scanOptions.PkgRelationships))
	}

	if opts.Scanners.Enabled(types.VulnerabilityScanner) {
		log.WithPrefix(log.PrefixVulnerability).Info("Vulnerability scanning is enabled")
	}

	// Misconfig ScannerOption is filled only when config scanning is enabled.
	var configScannerOptions misconf.ScannerOption
	if opts.Scanners.Enabled(types.MisconfigScanner) || opts.ImageConfigScanners.Enabled(types.MisconfigScanner) {
		var err error
		configScannerOptions, err = initMisconfScannerOption(ctx, opts)
		if err != nil {
			return ScannerConfig{}, types.ScanOptions{}, err
		}
	}

	// Do not load config file for secret scanning
	if opts.Scanners.Enabled(types.SecretScanner) {
		logger := log.WithPrefix(log.PrefixSecret)
		logger.Info("Secret scanning is enabled")
		if nonSecrets := lo.Without(opts.Scanners, types.SecretScanner, types.SBOMScanner); len(nonSecrets) > 0 {
			logger.Info(fmt.Sprintf(
				"If your scanning is slow, please try '--scanners %s' to disable secret scanning",
				strings.Join(xstrings.ToStringSlice(nonSecrets), ",")))
		}
		// e.g. https://trivy.dev/latest/docs/scanner/secret/#recommendation
		logger.Info(fmt.Sprintf("Please see %s for faster secret detection", doc.URL("/docs/scanner/secret/", "recommendation")))
	} else {
		opts.SecretConfigPath = ""
	}

	if opts.Scanners.Enabled(types.LicenseScanner) {
		logger := log.WithPrefix(log.PrefixLicense)
		if opts.LicenseFull {
			logger.Info("Full license scanning is enabled")
		} else {
			logger.Info("License scanning is enabled")
		}
	}

	// SPDX and CycloneDX need to calculate digests for package files
	var fileChecksum bool
	if opts.Format == types.FormatSPDXJSON || opts.Format == types.FormatSPDX || opts.Format == types.FormatCycloneDX {
		fileChecksum = true
	}

	// Disable the post handler for filtering system file when detection priority is comprehensive.
	disabledHandlers := lo.Ternary(opts.DetectionPriority == ftypes.PriorityComprehensive,
		[]ftypes.HandlerType{ftypes.SystemFileFilteringPostHandler}, nil)

	return ScannerConfig{
		Target:             target,
		CacheOptions:       opts.CacheOpts(),
		RemoteCacheOptions: opts.RemoteCacheOpts(),
		ServerOption:       opts.ClientScannerOpts(),
		ArtifactOption: artifact.Option{
			DisabledAnalyzers: disabledAnalyzers(opts),
			DisabledHandlers:  disabledHandlers,
			FilePatterns:      opts.FilePatterns,
			Parallel:          opts.Parallel,
			Offline:           opts.OfflineScan,
			NoProgress:        opts.NoProgress || opts.Quiet,
			Insecure:          opts.Insecure,
			RepoBranch:        opts.RepoBranch,
			RepoCommit:        opts.RepoCommit,
			RepoTag:           opts.RepoTag,
			SBOMSources:       opts.SBOMSources,
			RekorURL:          opts.RekorURL,
			AWSRegion:         opts.Region,
			AWSEndpoint:       opts.Endpoint,
			FileChecksum:      fileChecksum,
			DetectionPriority: opts.DetectionPriority,

			// For image scanning
			ImageOption: ftypes.ImageOptions{
				RegistryOptions: opts.RegistryOpts(),
				DockerOptions: ftypes.DockerOptions{
					Host: opts.DockerHost,
				},
				PodmanOptions: ftypes.PodmanOptions{
					Host: opts.PodmanHost,
				},
				ImageSources: opts.ImageSources,
				MaxImageSize: opts.MaxImageSize,
			},

			// For misconfiguration scanning
			MisconfScannerOption: configScannerOptions,

			// For secret scanning
			SecretScannerOption: analyzer.SecretScannerOption{
				ConfigPath: opts.SecretConfigPath,
			},

			// For license scanning
			LicenseScannerOption: analyzer.LicenseScannerOption{
				Full:                      opts.LicenseFull,
				ClassifierConfidenceLevel: opts.LicenseConfidenceLevel,
			},

			// For file walking
			WalkerOption: walker.Option{
				SkipFiles: opts.SkipFiles,
				SkipDirs:  opts.SkipDirs,
			},
		},
	}, scanOptions, nil
}

func (r *runner) scan(ctx context.Context, opts flag.Options, initializeService InitializeScanService) (types.Report, error) {
	scannerConfig, scanOptions, err := r.initScannerConfig(ctx, opts)
	if err != nil {
		return types.Report{}, err
	}
	s, cleanup, err := initializeService(ctx, scannerConfig)
	if err != nil {
		return types.Report{}, xerrors.Errorf("unable to initialize a scan service: %w", err)
	}
	defer cleanup()

	report, err := s.ScanArtifact(ctx, scanOptions)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan failed: %w", err)
	}
	return report, nil
}

func initMisconfScannerOption(ctx context.Context, opts flag.Options) (misconf.ScannerOption, error) {
	ctx = log.WithContextPrefix(ctx, log.PrefixMisconfiguration)
	log.InfoContext(ctx, "Misconfiguration scanning is enabled")

	var downloadedPolicyPath string
	var disableEmbedded bool

	c, err := policy.NewClient(opts.CacheDir, opts.Quiet, opts.MisconfOptions.ChecksBundleRepository)
	if err != nil {
		return misconf.ScannerOption{}, xerrors.Errorf("check client error: %w", err)
	}

	downloadedPolicyPath, err = operation.InitBuiltinChecks(ctx, c, opts.SkipCheckUpdate, opts.RegistryOpts())
	if err != nil {
		log.ErrorContext(ctx, "Falling back to embedded checks", log.Err(err))
	} else {
		log.DebugContext(ctx, "Checks successfully loaded from disk")
		disableEmbedded = true
	}

	policyPaths := slices.Clone(opts.CheckPaths)
	if downloadedPolicyPath != "" {
		policyPaths = append(policyPaths, downloadedPolicyPath)
	}

	configSchemas, err := misconf.LoadConfigSchemas(opts.ConfigFileSchemas)
	if err != nil {
		return misconf.ScannerOption{}, xerrors.Errorf("load schemas error: %w", err)
	}

	misconfOpts := misconf.ScannerOption{
		Trace:                    opts.RegoOptions.Trace,
		Namespaces:               append(opts.CheckNamespaces, rego.BuiltinNamespaces()...),
		PolicyPaths:              policyPaths,
		DataPaths:                opts.DataPaths,
		HelmValues:               opts.HelmValues,
		HelmValueFiles:           opts.HelmValueFiles,
		HelmFileValues:           opts.HelmFileValues,
		HelmStringValues:         opts.HelmStringValues,
		HelmAPIVersions:          opts.HelmAPIVersions,
		HelmKubeVersion:          opts.HelmKubeVersion,
		TerraformTFVars:          opts.TerraformTFVars,
		CloudFormationParamVars:  opts.CloudFormationParamVars,
		K8sVersion:               opts.K8sVersion,
		DisableEmbeddedPolicies:  disableEmbedded,
		DisableEmbeddedLibraries: disableEmbedded,
		IncludeDeprecatedChecks:  opts.IncludeDeprecatedChecks,
		TfExcludeDownloaded:      opts.TfExcludeDownloaded,
		RawConfigScanners:        opts.RawConfigScanners,
		FilePatterns:             opts.FilePatterns,
		ConfigFileSchemas:        configSchemas,
		SkipFiles:                opts.SkipFiles,
		SkipDirs:                 opts.SkipDirs,
	}

	regoScanner, err := misconf.InitRegoScanner(misconfOpts)
	if err != nil {
		return misconf.ScannerOption{}, xerrors.Errorf("init Rego scanner: %w", err)
	}

	misconfOpts.RegoScanner = regoScanner
	return misconfOpts, nil
}
