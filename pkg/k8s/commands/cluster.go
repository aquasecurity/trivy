package commands

import (
	"context"

	"golang.org/x/xerrors"

	trivy_checks "github.com/aquasecurity/trivy-checks"
	k8sArtifacts "github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
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
		artifacts, err = trivyk8s.New(cluster).ListClusterBomInfo(ctx)
		if err != nil {
			return xerrors.Errorf("get k8s artifacts with node info error: %w", err)
		}
	case types.FormatJSON, types.FormatTable:
		k8sOpts := []trivyk8s.K8sOption{
			trivyk8s.WithExcludeNamespaces(opts.ExcludeNamespaces),
			trivyk8s.WithIncludeNamespaces(opts.IncludeNamespaces),
			trivyk8s.WithExcludeKinds(opts.ExcludeKinds),
			trivyk8s.WithIncludeKinds(opts.IncludeKinds),
			trivyk8s.WithExcludeOwned(opts.ExcludeOwned),
		}
		if opts.Scanners.AnyEnabled(types.MisconfigScanner) && !opts.DisableNodeCollector {
			artifacts, err = trivyk8s.New(cluster, k8sOpts...).ListArtifactAndNodeInfo(ctx, nodeCollectorOptions(ctx, opts)...)
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
		log.InfoContext(ctx, "Node scanning is enabled")
		log.InfoContext(ctx, "If you want to disable Node scanning via an in-cluster Job, please try '--disable-node-collector' to disable the Node-Collector job.")
	}
	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}

func nodeCollectorOptions(ctx context.Context, opts flag.Options) []trivyk8s.NodeCollectorOption {
	nodeCollectorOptions := []trivyk8s.NodeCollectorOption{
		trivyk8s.WithScanJobNamespace(opts.NodeCollectorNamespace),
		trivyk8s.WithIgnoreLabels(opts.ExcludeNodes),
		trivyk8s.WithScanJobImageRef(opts.NodeCollectorImageRef),
		trivyk8s.WithTolerations(opts.Tolerations),
	}

	ctx = log.WithContextPrefix(ctx, log.PrefixMisconfiguration)
	contentPath, err := operation.InitBuiltinChecks(ctx, opts.CacheDir, opts.Quiet, opts.SkipCheckUpdate,
		opts.MisconfOptions.ChecksBundleRepository, opts.RegistryOpts())
	if err != nil {
		log.Error("Falling back to embedded checks", log.Err(err))
		nodeCollectorOptions = append(nodeCollectorOptions,
			[]trivyk8s.NodeCollectorOption{
				trivyk8s.WithEmbeddedCommandFileSystem(trivy_checks.EmbeddedK8sCommandsFileSystem),
				trivyk8s.WithEmbeddedNodeConfigFilesystem(trivy_checks.EmbeddedConfigCommandsFileSystem),
			}...)
	}

	complianceCommandsIDs := getComplianceCommands(opts)
	nodeCollectorOptions = append(nodeCollectorOptions, []trivyk8s.NodeCollectorOption{
		trivyk8s.WithCommandPaths(contentPath),
		trivyk8s.WithSpecCommandIds(complianceCommandsIDs),
	}...)
	return nodeCollectorOptions
}

func getComplianceCommands(opts flag.Options) []string {
	var commands []string
	if opts.Compliance.Spec.ID != "" {
		for _, control := range opts.Compliance.Spec.Controls {
			for _, command := range control.Commands {
				if command.ID != "" {
					commands = append(commands, command.ID)
				}
			}
		}
	}
	return commands
}
