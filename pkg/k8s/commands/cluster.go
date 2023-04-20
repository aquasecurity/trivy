package commands

import (
	"context"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
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
	var artifacts []*artifacts.Artifact
	var err error
	if opts.Scanners.AnyEnabled(types.MisconfigScanner) && slices.Contains(opts.Components, "infra") {
		artifacts, err = trivyk8s.New(cluster, log.Logger).ListArtifactAndNodeInfo(ctx, opts.Tolerations...)
		if err != nil {
			return xerrors.Errorf("get k8s artifacts with node info error: %w", err)
		}
	} else {
		artifacts, err = trivyk8s.New(cluster, log.Logger).ListArtifacts(ctx)
		if err != nil {
			return xerrors.Errorf("get k8s artifacts error: %w", err)
		}
	}

	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}
