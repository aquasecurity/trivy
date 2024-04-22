package commands

import (
	"context"

	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy/pkg/flag"
)

// namespaceRun runs scan on kubernetes cluster
func namespaceRun(ctx context.Context, opts flag.Options, cluster k8s.Cluster) error {
	// TODO: replace with slog.Logger
	logger, _ := zap.NewProduction()

	if err := validateReportArguments(opts); err != nil {
		return err
	}
	var trivyk trivyk8s.TrivyK8S
	if opts.AllNamespaces {
		trivyk = trivyk8s.New(cluster, logger.Sugar()).AllNamespaces()
	} else {
		trivyk = trivyk8s.New(cluster, logger.Sugar()).Namespace(getNamespace(opts, cluster.GetCurrentNamespace()))
	}

	artifacts, err := trivyk.ListArtifacts(ctx)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}

func getNamespace(opts flag.Options, currentNamespace string) string {
	if opts.K8sOptions.Namespace != "" {
		return opts.K8sOptions.Namespace
	}

	return currentNamespace
}
