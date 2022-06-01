package commands

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
)

// NamespaceRun runs scan on kubernetes cluster
func NamespaceRun(cliCtx *cli.Context) error {
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

	trivyk8s := trivyk8s.New(cluster).Namespace(getNamespace(cluster, opt))

	artifacts, err := trivyk8s.ListArtifacts(cliCtx.Context)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	return run(cliCtx.Context, opt, cluster.GetCurrentContext(), artifacts)
}

func getNamespace(cluster k8s.Cluster, opt cmd.Option) string {
	if len(opt.KubernetesOption.Namespace) > 0 {
		return opt.KubernetesOption.Namespace
	}

	return cluster.GetCurrentNamespace()
}
