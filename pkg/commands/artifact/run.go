package artifact

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/db"
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
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/doc"
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
)

var (
	SkipScan = errors.New("skip subsequent processes")
)

// InitializeScanner defines the initialize function signature of scanner
type InitializeScanner func(context.Context, ScannerConfig) (scanner.Scanner, func(), error)

type ScannerConfig struct {
	// e.g. image name and file path
	Target string

	// Cache
	CacheOptions       cache.Options
	RemoteCacheOptions cache.RemoteOptions

	// Client/Server options
	ServerOption client.ScannerOption

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
	initializeScanner InitializeScanner
	dbOpen            bool

	// WASM modules
	module *module.Manager
}

type RunnerOption func(*runner)

// WithInitializeScanner takes a custom scanner initialization function.
// It is useful when Trivy is imported as a library.
func WithInitializeScanner(f InitializeScanner) RunnerOption {
	return func(r *runner) {
		r.initializeScanner = f
	}
}

// NewRunner initializes Runner that provides scanning functionalities.
// It is possible to return SkipScan and it must be handled by caller.
func NewRunner(ctx context.Context, cliOptions flag.Options, opts ...RunnerOption) (Runner, error) {
	r := &runner{}
	for _, opt := range opts {
		opt(r)
	}

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
	return errs
}

func (r *runner) ScanImage(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Disable the lock file scanning
	opts.DisabledAnalyzers = analyzer.TypeLockfiles

	var s InitializeScanner
	switch {
	case opts.Input != "" && opts.ServerAddr == "":
		// Scan image tarball in standalone mode
		s = archiveStandaloneScanner
	case opts.Input != "" && opts.ServerAddr != "":
		// Scan image tarball in client/server mode
		s = archiveRemoteScanner
	case opts.Input == "" && opts.ServerAddr == "":
		// Scan container image in standalone mode
		s = imageStandaloneScanner
	case opts.Input == "" && opts.ServerAddr != "":
		// Scan container image in client/server mode
		s = imageRemoteScanner
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
	var s InitializeScanner
	if opts.ServerAddr == "" {
		// Scan filesystem in standalone mode
		s = filesystemStandaloneScanner
	} else {
		// Scan filesystem in client/server mode
		s = filesystemRemoteScanner
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanRepository(ctx context.Context, opts flag.Options) (types.Report, error) {
	// Do not scan OS packages
	opts.PkgTypes = []string{types.PkgTypeLibrary}

	// Disable the OS analyzers, individual package analyzers and SBOM analyzer
	opts.DisabledAnalyzers = append(analyzer.TypeIndividualPkgs, analyzer.TypeOSes...)
	opts.DisabledAnalyzers = append(opts.DisabledAnalyzers, analyzer.TypeSBOM)

	var s InitializeScanner
	if opts.ServerAddr == "" {
		// Scan repository in standalone mode
		s = repositoryStandaloneScanner
	} else {
		// Scan repository in client/server mode
		s = repositoryRemoteScanner
	}
	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanSBOM(ctx context.Context, opts flag.Options) (types.Report, error) {
	var s InitializeScanner
	if opts.ServerAddr == "" {
		// Scan cycloneDX in standalone mode
		s = sbomStandaloneScanner
	} else {
		// Scan cycloneDX in client/server mode
		s = sbomRemoteScanner
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) ScanVM(ctx context.Context, opts flag.Options) (types.Report, error) {
	// TODO: Does VM scan disable lock file..?
	opts.DisabledAnalyzers = analyzer.TypeLockfiles

	var s InitializeScanner
	if opts.ServerAddr == "" {
		// Scan virtual machine in standalone mode
		s = vmStandaloneScanner
	} else {
		// Scan virtual machine in client/server mode
		s = vmRemoteScanner
	}

	return r.scanArtifact(ctx, opts, s)
}

func (r *runner) scanArtifact(ctx context.Context, opts flag.Options, initializeScanner InitializeScanner) (types.Report, error) {
	if r.initializeScanner != nil {
		initializeScanner = r.initializeScanner
	}
	report, err := r.scan(ctx, opts, initializeScanner)
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

	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			// e.g. https://aquasecurity.github.io/trivy/latest/docs/configuration/
			log.WarnContext(ctx, fmt.Sprintf("Provide a higher timeout value, see %s", doc.URL("/docs/configuration/", "")))
		}
	}()

	if opts.ServerAddr != "" && opts.Scanners.AnyEnabled(types.MisconfigScanner, types.SecretScanner) {
		log.WarnContext(ctx,
			fmt.Sprintf(
				"Trivy runs in client/server mode, but misconfiguration and license scanning will be done on the client side, see %s",
				doc.URL("/docs/references/modes/client-server", ""),
			),
		)
	}

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

	r, err := NewRunner(ctx, opts)
	if err != nil {
		if errors.Is(err, SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
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
		return xerrors.Errorf("unknown target kind: %s", targetKind)
	}

	report, err := scanFunction(ctx, opts)
	if err != nil {
		return xerrors.Errorf("%s scan error: %w", targetKind, err)
	}

	report, err = r.Filter(ctx, opts, report)
	if err != nil {
		return xerrors.Errorf("filter error: %w", err)
	}

	if err = r.Report(ctx, opts, report); err != nil {
		return xerrors.Errorf("report error: %w", err)
	}

	return operation.Exit(opts, report.Results.Failed(), report.Metadata)
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

	// Filter only enabled misconfiguration scanners
	ma, err := filterMisconfigAnalyzers(opts.MisconfigScanners, analyzer.TypeConfigFiles)
	if err != nil {
		log.Error("Invalid misconfiguration scanners specified, defaulting to use all misconfig scanners",
			log.Any("scanners", opts.MisconfigScanners))
	} else {
		analyzers = append(analyzers, ma...)
	}

	// Do not perform misconfiguration scanning when it is not specified.
	if !opts.Scanners.AnyEnabled(types.MisconfigScanner, types.RBACScanner) {
		analyzers = append(analyzers, analyzer.TypeConfigFiles...)
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

func filterMisconfigAnalyzers(included, all []analyzer.Type) ([]analyzer.Type, error) {
	_, missing := lo.Difference(all, included)
	if len(missing) > 0 {
		return nil, xerrors.Errorf("invalid misconfiguration scanner specified %s valid scanners: %s", missing, all)
	}

	log.Debug("Enabling misconfiguration scanners", log.Any("scanners", included))
	return lo.Without(all, included...), nil
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
		logger.Info("If your scanning is slow, please try '--scanners vuln' to disable secret scanning")
		// e.g. https://aquasecurity.github.io/trivy/latest/docs/scanner/secret/#recommendation
		logger.Info(fmt.Sprintf("Please see also %s for faster secret detection", doc.URL("/docs/scanner/secret/", "recommendation")))
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

func (r *runner) scan(ctx context.Context, opts flag.Options, initializeScanner InitializeScanner) (types.Report, error) {
	scannerConfig, scanOptions, err := r.initScannerConfig(ctx, opts)
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
		return types.Report{}, xerrors.Errorf("scan failed: %w", err)
	}
	return report, nil
}

func initMisconfScannerOption(ctx context.Context, opts flag.Options) (misconf.ScannerOption, error) {
	ctx = log.WithContextPrefix(ctx, log.PrefixMisconfiguration)
	log.InfoContext(ctx, "Misconfiguration scanning is enabled")

	var downloadedPolicyPaths []string
	var disableEmbedded bool

	downloadedPolicyPaths, err := operation.InitBuiltinChecks(ctx, opts.CacheDir, opts.Quiet, opts.SkipCheckUpdate, opts.MisconfOptions.ChecksBundleRepository, opts.RegistryOpts())
	if err != nil {
		if !opts.SkipCheckUpdate {
			log.ErrorContext(ctx, "Falling back to embedded checks", log.Err(err))
		}
	} else {
		log.DebugContext(ctx, "Checks successfully loaded from disk")
		disableEmbedded = true
	}

	configSchemas, err := misconf.LoadConfigSchemas(opts.ConfigFileSchemas)
	if err != nil {
		return misconf.ScannerOption{}, xerrors.Errorf("load schemas error: %w", err)
	}

	return misconf.ScannerOption{
		Trace:                    opts.Trace,
		Namespaces:               append(opts.CheckNamespaces, rego.BuiltinNamespaces()...),
		PolicyPaths:              append(opts.CheckPaths, downloadedPolicyPaths...),
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
		FilePatterns:             opts.FilePatterns,
		ConfigFileSchemas:        configSchemas,
		SkipFiles:                opts.SkipFiles,
		SkipDirs:                 opts.SkipDirs,
	}, nil
}
