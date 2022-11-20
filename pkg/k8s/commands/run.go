package commands

import (
	"context"
	"errors"

	"github.com/spf13/viper"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	cr "github.com/aquasecurity/trivy/pkg/compliance/report"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/k8s/scanner"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	clusterArtifact = "cluster"
	allArtifact     = "all"
)

// Run runs a k8s scan
func Run(ctx context.Context, args []string, opts flag.Options) error {
	cluster, err := k8s.GetCluster(
		k8s.WithContext(opts.K8sOptions.ClusterContext),
		k8s.WithKubeConfig(opts.K8sOptions.KubeConfig),
	)
	if err != nil {
		return xerrors.Errorf("failed getting k8s cluster: %w", err)
	}

	switch args[0] {
	case clusterArtifact:
		return clusterRun(ctx, opts, cluster)
	case allArtifact:
		return namespaceRun(ctx, opts, cluster)
	default: // resourceArtifact
		return resourceRun(ctx, args, opts, cluster)
	}
}

type runner struct {
	flagOpts flag.Options
	cluster  string
}

func newRunner(flagOpts flag.Options, cluster string) *runner {
	return &runner{flagOpts, cluster}
}

func (r *runner) run(ctx context.Context, artifacts []*artifacts.Artifact) error {
	ctx, cancel := context.WithTimeout(ctx, r.flagOpts.Timeout)
	defer cancel()

	var err error
	defer func() {
		if xerrors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	runner, err := cmd.NewRunner(ctx, r.flagOpts)
	if err != nil {
		if errors.Is(err, cmd.SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
	}
	defer func() {
		if err := runner.Close(ctx); err != nil {
			log.Logger.Errorf("failed to close runner: %s", err)
		}
	}()

	s := scanner.NewScanner(r.cluster, runner, r.flagOpts)

	var complianceSpec spec.ComplianceSpec
	// set scanners types by spec
	if r.flagOpts.ReportOptions.Compliance != "" {
		cs, err := spec.GetComplianceSpec(r.flagOpts.ReportOptions.Compliance)
		if err != nil {
			return xerrors.Errorf("spec loading from file system error: %w", err)
		}
		if err = yaml.Unmarshal(cs, &complianceSpec); err != nil {
			return xerrors.Errorf("yaml unmarshal error: %w", err)
		}
		securityChecks, err := complianceSpec.SecurityChecks()
		if err != nil {
			return xerrors.Errorf("security check error: %w", err)
		}
		r.flagOpts.ScanOptions.SecurityChecks = securityChecks
	}

	rpt, err := s.Scan(ctx, artifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}

	if len(r.flagOpts.ReportOptions.Compliance) > 0 {
		var scanResults []types.Results
		for _, rss := range rpt.Vulnerabilities {
			scanResults = append(scanResults, rss.Results)
		}
		for _, rss := range rpt.Misconfigurations {
			scanResults = append(scanResults, rss.Results)
		}
		complianceReport, err := cr.BuildComplianceReport(scanResults, complianceSpec)
		if err != nil {
			return xerrors.Errorf("compliance report build error: %w", err)
		}
		return cr.Write(complianceReport, cr.Option{
			Format: r.flagOpts.Format,
			Report: r.flagOpts.ReportFormat,
			Output: r.flagOpts.Output})
	}

	if err := report.Write(rpt, report.Option{
		Format:         r.flagOpts.Format,
		Report:         r.flagOpts.ReportFormat,
		Output:         r.flagOpts.Output,
		Severities:     r.flagOpts.Severities,
		Components:     r.flagOpts.Components,
		SecurityChecks: r.flagOpts.ScanOptions.SecurityChecks,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	cmd.Exit(r.flagOpts, rpt.Failed())

	return nil
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
