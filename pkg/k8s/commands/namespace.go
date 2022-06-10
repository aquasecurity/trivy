package commands

import (
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
)

// namespaceRun runs scan on kubernetes cluster
func namespaceRun(cliCtx *cli.Context, opt cmd.Option, cluster k8s.Cluster) error {
	if err := validateReportArguments(cliCtx); err != nil {
		return err
	}

	trivyk8s := trivyk8s.New(cluster).Namespace(getNamespace(opt, cluster.GetCurrentNamespace()))

	artifacts, err := trivyk8s.ListArtifacts(cliCtx.Context)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	return run(cliCtx.Context, opt, cluster.GetCurrentContext(), artifacts)
}

func getNamespace(opt cmd.Option, currentNamespace string) string {
	if len(opt.KubernetesOption.Namespace) > 0 {
		return opt.KubernetesOption.Namespace
	}

	return currentNamespace
}
