package k8s

import (
	"context"
	"errors"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
)

// Run runs scan on kubernetes cluster
func Run(cliCtx *cli.Context) error {
	// Full-cluster scanning with '--format table' without explicit '--report all' is not allowed so that it won't mess up user's terminal.
	if cliCtx.String("report") == "all" &&
		!cliCtx.IsSet("report") &&
		cliCtx.String("format") == "table" &&
		!cliCtx.Args().Present() {

		m := "All the results in the table format can mess up your terminal. Use \"--report all\" to tell Trivy to output it to your terminal anyway, or consider \"--report summary\" to show the summary output."

		return xerrors.New(m)
	}

	opt, err := cmd.InitOption(cliCtx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	ctx, cancel := context.WithTimeout(cliCtx.Context, opt.Timeout)
	defer cancel()

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
	defer runner.Close()

	cluster, err := k8s.GetCluster()
	if err != nil {
		return xerrors.Errorf("get k8s cluster: %w", err)
	}

	// get kubernetes scannable artifacts
	artifacts, err := getArtifacts(ctx, cliCtx.Args(), cluster, opt.KubernetesOption.Namespace)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	s := &scanner{
		cluster: cluster.GetCurrentContext(),
		runner:  runner,
		opt:     opt,
	}

	return run(ctx, s, opt, artifacts)
}

func run(ctx context.Context, s *scanner, opt cmd.Option, artifacts []*artifacts.Artifact) error {
	report, err := s.run(ctx, artifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}

	if err = write(report, Option{
		Format:     opt.Format,
		Report:     opt.KubernetesOption.ReportFormat,
		Output:     opt.Output,
		Severities: opt.Severities,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	cmd.Exit(opt, report.Failed())

	return nil
}

func getArtifacts(ctx context.Context, args cli.Args, cluster k8s.Cluster, namespace string) ([]*artifacts.Artifact, error) {
	trivyk8s := trivyk8s.New(cluster)

	if !args.Present() {
		return trivyk8s.Namespace(namespace).ListArtifacts(ctx)
	}

	// if scanning single resource, and namespace is empty
	// uses default namespace
	if len(namespace) == 0 {
		namespace = cluster.GetCurrentNamespace()
	}

	kind, name, err := extractKindAndName(args)
	if err != nil {
		return nil, err
	}

	artifact, err := trivyk8s.Namespace(namespace).GetArtifact(ctx, kind, name)
	if err != nil {
		return nil, err
	}

	return []*artifacts.Artifact{artifact}, nil
}

func extractKindAndName(args cli.Args) (string, string, error) {
	switch args.Len() {
	case 1:
		s := strings.Split(args.Get(0), "/")
		if len(s) != 2 {
			return "", "", xerrors.Errorf("can't parse arguments: %v", args.Slice())
		}

		return s[0], s[1], nil
	case 2:
		return args.Get(0), args.Get(1), nil
	}

	return "", "", xerrors.Errorf("can't parse arguments: %v", args.Slice())
}
