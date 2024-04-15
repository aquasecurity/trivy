package commands

import (
	"context"

<<<<<<< HEAD
	"golang.org/x/exp/slices"
=======
	"go.uber.org/zap"
>>>>>>> 660c113f6 (feat: change flag name to disable-node-collector)
	"golang.org/x/xerrors"

	k8sArtifacts "github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"
)

// clusterRun runs scan on kubernetes cluster
func clusterRun(ctx context.Context, opts flag.Options, cluster k8s.Cluster) error {
<<<<<<< HEAD
=======
	// TODO: replace with log.Logger
	logger, _ := zap.NewProduction()
>>>>>>> 660c113f6 (feat: change flag name to disable-node-collector)
	if err := validateReportArguments(opts); err != nil {
		return err
	}
	var artifacts []*k8sArtifacts.Artifact
	var err error
	switch opts.Format {
	case types.FormatCycloneDX:
		artifacts, err = trivyk8s.New(cluster).ListClusterBomInfo(ctx)
		if err != nil {
			return xerrors.Errorf("get k8s artifacts with node info error: %w", err)
		}
	case types.FormatJSON, types.FormatTable:
<<<<<<< HEAD
		k8sOpts := []trivyk8s.K8sOption{
			trivyk8s.WithExcludeNamespaces(opts.ExcludeNamespaces),
			trivyk8s.WithIncludeNamespaces(opts.IncludeNamespaces),
			trivyk8s.WithExcludeKinds(opts.ExcludeKinds),
			trivyk8s.WithIncludeKinds(opts.IncludeKinds),
			trivyk8s.WithExcludeOwned(opts.ExcludeOwned),
		}
		if opts.Scanners.AnyEnabled(types.MisconfigScanner) && !opts.DisableNodeCollector {
			artifacts, err = trivyk8s.New(cluster, k8sOpts...).ListArtifactAndNodeInfo(ctx,
=======

		if opts.Scanners.AnyEnabled(types.MisconfigScanner) && !opts.DisableNodeCollector {
			artifacts, err = trivyk8s.New(cluster, logger.Sugar(), trivyk8s.WithExcludeOwned(opts.ExcludeOwned)).ListArtifactAndNodeInfo(ctx,
>>>>>>> 660c113f6 (feat: change flag name to disable-node-collector)
				trivyk8s.WithScanJobNamespace(opts.NodeCollectorNamespace),
				trivyk8s.WithIgnoreLabels(opts.ExcludeNodes),
				trivyk8s.WithScanJobImageRef(opts.NodeCollectorImageRef),
				trivyk8s.WithTolerations(opts.Tolerations))
			if err != nil {
				return xerrors.Errorf("get k8s artifacts with node info error: %w", err)
			}
		} else {
			artifacts, err = trivyk8s.New(cluster, k8sOpts...).ListArtifacts(ctx)
			if err != nil {
				return xerrors.Errorf("get k8s artifacts error: %w", err)
			}
		}
	default:
		return xerrors.Errorf(`unknown format %q. Use "json" or "table" or "cyclonedx"`, opts.Format)
	}

	if !opts.DisableNodeCollector && !opts.Quiet {
		logger.Sugar().Info("Node scanning is enabled")
		logger.Sugar().Info("If you want to disable Node scanning via an in-cluster Job, please try '--disable-node-collector' to disable the Node-Collector job.")
	}
	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}
