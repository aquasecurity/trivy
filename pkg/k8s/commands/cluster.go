package commands

import (
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
)

// clusterRun runs scan on kubernetes cluster
func clusterRun(cliCtx *cli.Context, opt cmd.Option, cluster k8s.Cluster) error {
	if err := validateReportArguments(cliCtx); err != nil {
		return err
	}

	artifacts, err := trivyk8s.New(cluster, log.Logger).ListArtifacts(cliCtx.Context)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	return run(cliCtx.Context, opt, cluster.GetCurrentContext(), artifacts)
}
