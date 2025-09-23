package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	tdb "github.com/aquasecurity/trivy-db/pkg/db"
	k8sArtifacts "github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy/pkg/cache"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	cr "github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	image2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	local2 "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/flag"
	k8sRep "github.com/aquasecurity/trivy/pkg/k8s"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/k8s/scanner"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	scanlocal "github.com/aquasecurity/trivy/pkg/scan/local"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/doc"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	"os"
)

// Run runs a k8s scan
func Run(ctx context.Context, args []string, opts flag.Options) error {
	clusterOptions := []k8s.ClusterOption{
		k8s.WithKubeConfig(opts.K8sOptions.KubeConfig),
		k8s.WithBurst(opts.K8sOptions.Burst),
		k8s.WithQPS(opts.K8sOptions.QPS),
	}
	if len(args) > 0 {
		clusterOptions = append(clusterOptions, k8s.WithContext(args[0]))
	}
	cluster, err := k8s.GetCluster(clusterOptions...)
	if err != nil {
		return xerrors.Errorf("failed getting k8s cluster: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)

	defer func() {
		cancel()
		if errors.Is(err, context.DeadlineExceeded) {
			// e.g. https://trivy.dev/latest/docs/configuration
			log.WarnContext(ctx, fmt.Sprintf("Provide a higher timeout value, see %s", doc.URL("/docs/configuration/", "")))
		}
	}()
	opts.K8sVersion = cluster.GetClusterVersion()
	return clusterRun(ctx, opts, cluster)
}

type runner struct {
	flagOpts flag.Options
	cluster  string
}

func newRunner(flagOpts flag.Options, cluster string) *runner {
	return &runner{
		flagOpts,
		cluster,
	}
}

func (r *runner) run(ctx context.Context, artifacts []*k8sArtifacts.Artifact) error {
	// Create a shared local cache (e.g. fanal.db) reused across all image scans
	sharedCache, sharedCleanup, err := cache.New(r.flagOpts.CacheOpts())
	if err != nil {
		return xerrors.Errorf("init shared cache error: %w", err)
	}
	defer func() { _ = sharedCache.Close() }()

	// Inject initializer that reuses the shared cache for standalone image scans
	initWithShared := withK8sSharedCacheInitializer(sharedCache)

	runner, err := cmd.NewRunner(ctx, r.flagOpts, cmd.TargetK8s, cmd.WithInitializeService(initWithShared))
	if err != nil {
		if errors.Is(err, cmd.SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
	}
	defer func() {
		if err := runner.Close(ctx); err != nil {
			log.ErrorContext(ctx, "failed to close runner: %s", err)
		}
		// Ensure we cleanup the shared cache at the very end
		sharedCleanup()
	}()

	s := scanner.NewScanner(r.cluster, runner, r.flagOpts)

	// set scanners types by spec
	if r.flagOpts.Compliance.Spec.ID != "" {
		scanners, err := r.flagOpts.Compliance.Scanners()
		if err != nil {
			return xerrors.Errorf("scanner error: %w", err)
		}
		r.flagOpts.ScanOptions.Scanners = scanners
	}
	var rpt report.Report
	log.Info("Scanning K8s...", log.String("K8s", r.cluster))
	rpt, err = s.Scan(ctx, artifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}

	output, cleanup, err := r.flagOpts.OutputWriter(ctx)
	if err != nil {
		return xerrors.Errorf("failed to create output file: %w", err)
	}
	defer cleanup()

	if r.flagOpts.Compliance.Spec.ID != "" {
		var scanResults []types.Results
		for _, rss := range rpt.Resources {
			scanResults = append(scanResults, rss.Results)
		}
		complianceReport, err := cr.BuildComplianceReport(scanResults, r.flagOpts.Compliance)
		if err != nil {
			return xerrors.Errorf("compliance report build error: %w", err)
		}
		return cr.Write(ctx, complianceReport, cr.Option{
			Format: r.flagOpts.Format,
			Report: r.flagOpts.ReportFormat,
			Output: output,
		})
	}

	if err := k8sRep.Write(ctx, rpt, report.Option{
		Format:     r.flagOpts.Format,
		Report:     r.flagOpts.ReportFormat,
		Output:     output,
		Severities: r.flagOpts.Severities,
		Scanners:   r.flagOpts.ScanOptions.Scanners,
		APIVersion: r.flagOpts.AppVersion,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	return operation.Exit(r.flagOpts, rpt.Failed(), types.Metadata{})
}

// withK8sSharedCacheInitializer returns a custom initializer that reuses the provided
// cache for standalone image scans. For filesystem scans, it respects the backend
// passed via conf.CacheOptions (e.g., memory set by scanMisconfigs). For client/server
// mode, it uses the remote cache as usual.
func withK8sSharedCacheInitializer(shared cache.Cache) cmd.InitializeScanService {
	return func(ctx context.Context, conf cmd.ScannerConfig) (scan.Service, func(), error) {
		// Client/server mode -> use remote service and remote cache
		if conf.ServerOption.RemoteURL != "" {
			service := client.NewService(conf.ServerOption)

			// Determine if target is filesystem or image by checking local path existence
			if isFilesystemTarget(conf.Target) {
				remoteCache := cache.NewRemoteCache(ctx, conf.RemoteCacheOptions)
				fs := walker.NewFS()
				artifact, err := local2.NewArtifact(conf.Target, remoteCache, fs, conf.ArtifactOption)
				if err != nil {
					return scan.Service{}, func() {}, xerrors.Errorf("init remote fs artifact: %w", err)
				}
				return scan.NewService(service, artifact), func() {}, nil
			}

			// Image in client/server mode
			img, imgCleanup, err := image.NewContainerImage(ctx, conf.Target, conf.ArtifactOption.ImageOption)
			if err != nil {
				return scan.Service{}, func() {}, xerrors.Errorf("init remote image: %w", err)
			}
			remoteCache := cache.NewRemoteCache(ctx, conf.RemoteCacheOptions)
			artifact, err := image2.NewArtifact(img, remoteCache, conf.ArtifactOption)
			if err != nil {
				imgCleanup()
				return scan.Service{}, func() {}, xerrors.Errorf("init remote image artifact: %w", err)
			}
			return scan.NewService(service, artifact), func() { imgCleanup() }, nil
		}

		// Standalone mode -> build local service with cache
		// Respect explicit memory backend if requested in conf.CacheOptions
		useShared := conf.CacheOptions.Backend == "" || conf.CacheOptions.Backend == "fs"
		var cacheToUse cache.Cache
		var memCleanup func()
		if useShared {
			cacheToUse = shared
			memCleanup = func() {}
		} else {
			// e.g. memory backend set by scanMisconfigs
			c, cleanup, err := cache.New(conf.CacheOptions)
			if err != nil {
				return scan.Service{}, func() {}, xerrors.Errorf("init local cache: %w", err)
			}
			cacheToUse = c
			memCleanup = cleanup
		}

		// Common local components
		ap := applier.NewApplier(cacheToUse)
		oScanner := ospkg.NewScanner()
		lScanner := langpkg.NewScanner()
		vClient := vulnerability.NewClient(tdb.Config{})
		localSvc := scanlocal.NewService(ap, oScanner, lScanner, vClient)

		if isFilesystemTarget(conf.Target) {
			fs := walker.NewFS()
			artifact, err := local2.NewArtifact(conf.Target, cacheToUse, fs, conf.ArtifactOption)
			if err != nil {
				memCleanup()
				return scan.Service{}, func() {}, xerrors.Errorf("init fs artifact: %w", err)
			}
			return scan.NewService(localSvc, artifact), func() { memCleanup() }, nil
		}

		// Image in standalone mode
		img, imgCleanup, err := image.NewContainerImage(ctx, conf.Target, conf.ArtifactOption.ImageOption)
		if err != nil {
			memCleanup()
			return scan.Service{}, func() {}, xerrors.Errorf("init image: %w", err)
		}
		artifact, err := image2.NewArtifact(img, cacheToUse, conf.ArtifactOption)
		if err != nil {
			imgCleanup()
			memCleanup()
			return scan.Service{}, func() {}, xerrors.Errorf("init image artifact: %w", err)
		}
		return scan.NewService(localSvc, artifact), func() {
			imgCleanup()
			memCleanup()
		}, nil
	}
}

func isFilesystemTarget(target string) bool {
	if target == "" {
		return false
	}
	if st, err := os.Stat(target); err == nil && (st.Mode().IsDir() || st.Mode().IsRegular()) {
		return true
	}
	return false
}

// Full-cluster scanning with '--format table' without explicit '--report all' is not allowed so that it won't mess up user's terminal.
// To show all the results, user needs to specify "--report all" explicitly
// even though the default value of "--report" is "all".
//
// e.g.
// $ trivy k8s --report all
//
// Or they can use "--format json" with implicit "--report all".
//
// e.g. $ trivy k8s --format json // All the results are shown in JSON
func validateReportArguments(opts flag.Options) error {
	if opts.ReportFormat == "all" &&
		!viper.IsSet("report") &&
		opts.Format == "table" {

		m := "All the results in the table format can mess up your terminal. Use \"--report all\" to tell Trivy to output it to your terminal anyway, or consider \"--report summary\" to show the summary output."

		return xerrors.New(m)
	}

	return nil
}
