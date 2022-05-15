package k8s

import (
	"context"
	"errors"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
)

// Run runs scan on kubernetes cluster
func Run(cliCtx *cli.Context) error {
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
	artifacts, err := getArtifacts(ctx, cluster, opt.KubernetesOption.Namespace)
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

	if err = write(report, pkgReport.Option{
		Format: opt.KubernetesOption.ReportFormat,
		Output: opt.Output,
	}, opt.Severities); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	cmd.Exit(opt, report.Failed())

	return nil
}

func getArtifacts(ctx context.Context, cluster k8s.Cluster, namespace string) ([]*artifacts.Artifact, error) {
	return trivyk8s.New(cluster).Namespace(namespace).ListArtifacts(ctx)
}
