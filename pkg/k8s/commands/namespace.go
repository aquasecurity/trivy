package commands

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

// namespaceRun runs scan on kubernetes cluster
func namespaceRun(ctx context.Context, opts flag.Options, cluster k8s.Cluster) error {
	if err := validateReportArguments(opts); err != nil {
		return err
	}

	trivyk8s := trivyk8s.New(cluster, log.Logger).Namespace(getNamespace(opts, cluster.GetCurrentNamespace()))

	artifacts, err := trivyk8s.ListArtifacts(ctx)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	return run(ctx, opts, cluster.GetCurrentContext(), artifacts)
}

func getNamespace(opts flag.Options, currentNamespace string) string {
	if len(opts.KubernetesOptions.Namespace) > 0 {
		return opts.KubernetesOptions.Namespace
	}

	return currentNamespace
}
