package commands

import (
	"context"
	"errors"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/k8s"
	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
)

// run runs scan on kubernetes cluster
func run(ctx context.Context, opt cmd.Option, cluster string, artifacts []*artifacts.Artifact) error {
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	var err error
	defer func() {
		if xerrors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	runner, err := cmd.NewRunner(opt)
	if err != nil {
		if errors.Is(err, cmd.SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
	}
	defer func() {
		if err := runner.Close(); err != nil {
			log.Logger.Errorf("failed to close runner: %s", err)
		}
	}()

	s := k8s.NewScanner(cluster, runner, opt)

	r, err := s.Scan(ctx, artifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}

	if err := k8s.Write(r, k8s.Option{
		Format:     opt.Format,
		Report:     opt.KubernetesOption.ReportFormat,
		Output:     opt.Output,
		Severities: opt.Severities,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	cmd.Exit(opt, r.Failed())

	return nil
}

// Full-cluster scanning with '--format table' without explicit '--report all' is not allowed so that it won't mess up user's terminal.
// To show all the results, user needs to specify "--report all" explicitly
// even though the default value of "--report" is "all".
//
// e.g. $ trivy k8s cluster --report all
//      $ trivy k8s all --report all
//
// Or they can use "--format json" with implicit "--report all".
//
// e.g. $ trivy k8s --format json // All the results are shown in JSON
//
// Single resource scanning is allowed with implicit "--report all".
//
// e.g. $ trivy k8s pod myapp
func validateReportArguments(cliCtx *cli.Context) error {
	if cliCtx.String("report") == "all" &&
		!cliCtx.IsSet("report") &&
		cliCtx.String("format") == "table" {

		m := "All the results in the table format can mess up your terminal. Use \"--report all\" to tell Trivy to output it to your terminal anyway, or consider \"--report summary\" to show the summary output."

		return xerrors.New(m)
	}

	return nil
}
