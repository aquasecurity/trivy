package commands

import (
	"context"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"

	"golang.org/x/xerrors"
)

// clusterRun runs scan on kubernetes cluster
func clusterRun(ctx context.Context, opts flag.Options, cluster k8s.Cluster) error {
	if err := validateReportArguments(opts); err != nil {
		return err
	}

	artifacts, err := trivyk8s.New(cluster, log.Logger).ListArtifacts(ctx)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}
