package k8s

import (
	"context"
	"errors"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"

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

	trivyk8s := trivyk8s.New(cluster).Namespace(opt.KubernetesOption.Namespace)

	// list all kubernetes scannable artifacts
	artifacts, err := trivyk8s.ListArtifacts(ctx)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	s := &scanner{runner, opt}

	report, err := s.run(ctx, artifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}
	report.ClusterName = cluster.GetCurrentContext()

	if err = write(report, pkgReport.Option{
		Format: opt.KubernetesOption.ReportFormat, // for now json is the default
		Output: opt.Output,
	}, opt.Severities); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	cmd.Exit(opt, report.Failed())

	return nil
}
