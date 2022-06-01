package commands

import (
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
)

// ClusterRun runs scan on kubernetes cluster
func ClusterRun(cliCtx *cli.Context) error {
	opt, err := InitOption(cliCtx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	err = validateReportArguments(cliCtx)
	if err != nil {
		return err
	}

	cluster, err := k8s.GetCluster(opt.KubernetesOption.ClusterContext)
	if err != nil {
		return xerrors.Errorf("get k8s cluster: %w", err)
	}

	artifacts, err := trivyk8s.New(cluster).ListArtifacts(cliCtx.Context)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	return run(cliCtx.Context, opt, cluster.GetCurrentContext(), artifacts)
}
