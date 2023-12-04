package commands

import (
	"context"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	k8sArtifacts "github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// clusterRun runs scan on kubernetes cluster
func clusterRun(ctx context.Context, opts flag.Options, cluster k8s.Cluster) error {
	if err := validateReportArguments(opts); err != nil {
		return err
	}
	var artifacts []*k8sArtifacts.Artifact
	var err error
	switch opts.Format {
	case types.FormatCycloneDX:
		artifacts, err = trivyk8s.New(cluster, log.Logger).ListClusterBomInfo(ctx)
		if err != nil {
			return xerrors.Errorf("get k8s artifacts with node info error: %w", err)
		}
	case types.FormatJSON, types.FormatTable:
		if opts.Scanners.AnyEnabled(types.MisconfigScanner) && slices.Contains(opts.Components, "infra") {
			artifacts, err = trivyk8s.New(cluster, log.Logger, trivyk8s.WithExcludeOwned(opts.ExcludeOwned)).ListArtifactAndNodeInfo(ctx,
				trivyk8s.WithScanJobNamespace(opts.NodeCollectorNamespace),
				trivyk8s.WithIgnoreLabels(opts.ExcludeNodes),
				trivyk8s.WithScanJobImageRef(opts.NodeCollectorImageRef),
				trivyk8s.WithTolerations(opts.Tolerations))
			if err != nil {
				return xerrors.Errorf("get k8s artifacts with node info error: %w", err)
			}
		} else {
			artifacts, err = trivyk8s.New(cluster, log.Logger).ListArtifacts(ctx)
			if err != nil {
				return xerrors.Errorf("get k8s artifacts error: %w", err)
			}
		}
	default:
		return xerrors.Errorf(`unknown format %q. Use "json" or "table" or "cyclonedx"`, opts.Format)
	}

	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}
