package commands

import (
	"context"
	"errors"

	"github.com/spf13/viper"

	"github.com/aquasecurity/trivy/pkg/flag"

	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/k8s/scanner"
	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
)

const (
	clusterArtifact = "cluster"
	allArtifact     = "all"
)

// Run runs a k8s scan
func Run(ctx context.Context, args []string, opts flag.Options) error {
	cluster, err := k8s.GetCluster(opts.K8sOptions.ClusterContext)
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

func run(ctx context.Context, opts flag.Options, cluster string, artifacts []*artifacts.Artifact) error {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var err error
	defer func() {
		if xerrors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	runner, err := cmd.NewRunner(ctx, opts)
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

	s := scanner.NewScanner(cluster, runner, opts)

	r, err := s.Scan(ctx, artifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}
	if err := report.Write(r, report.Option{
		Format:     opts.Format,
		Report:     opts.K8sOptions.ReportFormat,
		Output:     opts.Output,
		Severities: opts.Severities,
	}, opts.ScanOptions.SecurityChecks); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	cmd.Exit(opts, r.Failed())

	return nil
}

// Full-cluster scanning with '--format table' without explicit '--report all' is not allowed so that it won't mess up user's terminal.
// To show all the results, user needs to specify "--report all" explicitly
// even though the default value of "--report" is "all".
//
// e.g. $ trivy k8s --report all cluster
//      $ trivy k8s --report all all
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
