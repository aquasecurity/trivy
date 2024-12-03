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
			// e.g. https://aquasecurity.github.io/trivy/latest/docs/configuration
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
	runner, err := cmd.NewRunner(ctx, r.flagOpts)
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
// $ trivy k8s --report all cluster
// $ trivy k8s --report all all
//
// Or they can use "--format json" with implicit "--report all".
//
// e.g. $ trivy k8s --format json cluster // All the results are shown in JSON
//
// Single resource scanning is allowed with implicit "--report all".
//
// e.g. $ trivy k8s pod myapp
func validateReportArguments(opts flag.Options) error {
	if opts.ReportFormat == "all" &&
		!viper.IsSet("report") &&
		opts.Format == "table" {

		m := "All the results in the table format can mess up your terminal. Use \"--report all\" to tell Trivy to output it to your terminal anyway, or consider \"--report summary\" to show the summary output."

		return xerrors.New(m)
	}

	return nil
}
