package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	k8sArtifacts "github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	cr "github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/flag"
	k8sRep "github.com/aquasecurity/trivy/pkg/k8s"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/k8s/scanner"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version/doc"

	// Shared scan service wiring for custom initializer
	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	artimage "github.com/aquasecurity/trivy/pkg/fanal/artifact/image"
	artlocal "github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/scan/langpkg"
	localscan "github.com/aquasecurity/trivy/pkg/scan/local"
	"github.com/aquasecurity/trivy/pkg/scan/ospkg"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
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
	// Build a shared FS cache for image scans to avoid BoltDB conflicts
	cacheOpts := r.flagOpts.CacheOpts()

	var sharedCache cache.Cache
	var sharedCacheCleanup func()

	if cache.NewType(cacheOpts.Backend) == cache.TypeFS {
		var err error
		sharedCache, sharedCacheCleanup, err = cache.New(cacheOpts)
		if err != nil {
			return xerrors.Errorf("init shared cache error: %w", err)
		}
		// Ensure shared cache is closed after all scans
		defer func() {
			if sharedCacheCleanup != nil {
				sharedCacheCleanup()
			}
		}()
	}

	// Custom initializer that reuses the shared FS cache for image scans
	initWithSharedCache := func(initCtx context.Context, conf cmd.ScannerConfig) (scan.Service, func(), error) {
		// If memory backend is requested (e.g., for k8s misconfig), use a fresh in-memory cache
		if cache.NewType(conf.CacheOptions.Backend) == cache.TypeMemory {
			mem := cache.NewMemoryCache()

			app := applier.NewApplier(mem)
			osScanner := ospkg.NewScanner()
			langScanner := langpkg.NewScanner()
			vulnClient := vulnerability.NewClient(trivydb.Config{})
			svc := localscan.NewService(app, osScanner, langScanner, vulnClient)

			fs := walker.NewFS()
			art, err := artlocal.NewArtifact(conf.Target, mem, fs, conf.ArtifactOption)
			if err != nil {
				_ = mem.Close()
				return scan.Service{}, nil, xerrors.Errorf("unable to initialize filesystem artifact: %w", err)
			}
			return scan.NewService(svc, art), func() { _ = mem.Close() }, nil
		}

		// Default path: image scan with a shared FS cache
		if sharedCache == nil {
			// Fallback: create a one-off cache if not initialized
			tmpCache, tmpCleanup, err := cache.New(conf.CacheOptions)
			if err != nil {
				return scan.Service{}, nil, xerrors.Errorf("unable to initialize cache: %w", err)
			}
			app := applier.NewApplier(tmpCache)
			osScanner := ospkg.NewScanner()
			langScanner := langpkg.NewScanner()
			vulnClient := vulnerability.NewClient(trivydb.Config{})
			svc := localscan.NewService(app, osScanner, langScanner, vulnClient)

			img, cleanupImage, err := image.NewContainerImage(initCtx, conf.Target, conf.ArtifactOption.ImageOption)
			if err != nil {
				tmpCleanup()
				return scan.Service{}, nil, xerrors.Errorf("unable to initialize container image: %w", err)
			}
			art, err := artimage.NewArtifact(img, tmpCache, conf.ArtifactOption)
			if err != nil {
				cleanupImage()
				tmpCleanup()
				return scan.Service{}, nil, xerrors.Errorf("unable to initialize artifact: %w", err)
			}
			return scan.NewService(svc, art), func() { cleanupImage(); tmpCleanup() }, nil
		}

		// Use the shared FS cache
		app := applier.NewApplier(sharedCache)
		osScanner := ospkg.NewScanner()
		langScanner := langpkg.NewScanner()
		vulnClient := vulnerability.NewClient(trivydb.Config{})
		svc := localscan.NewService(app, osScanner, langScanner, vulnClient)

		img, cleanupImage, err := image.NewContainerImage(initCtx, conf.Target, conf.ArtifactOption.ImageOption)
		if err != nil {
			return scan.Service{}, nil, xerrors.Errorf("unable to initialize container image: %w", err)
		}
		art, err := artimage.NewArtifact(img, sharedCache, conf.ArtifactOption)
		if err != nil {
			cleanupImage()
			return scan.Service{}, nil, xerrors.Errorf("unable to initialize artifact: %w", err)
		}
		// Do not close the shared cache here; only close the image
		return scan.NewService(svc, art), func() { cleanupImage() }, nil
	}

	runner, err := cmd.NewRunner(ctx, r.flagOpts, cmd.TargetK8s, cmd.WithInitializeService(initWithSharedCache))
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
