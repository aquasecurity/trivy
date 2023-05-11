package commands

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ms "github.com/mitchellh/mapstructure"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	cr "github.com/aquasecurity/trivy/pkg/compliance/report"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	k8sRep "github.com/aquasecurity/trivy/pkg/k8s"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/k8s/scanner"
	"github.com/aquasecurity/trivy/pkg/log"
	rep "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	clusterArtifact = "cluster"
	allArtifact     = "all"
	schemaVersion   = 0
)

// Run runs a k8s scan
func Run(ctx context.Context, args []string, opts flag.Options) error {
	cluster, err := k8s.GetCluster(
		k8s.WithContext(opts.K8sOptions.ClusterContext),
		k8s.WithKubeConfig(opts.K8sOptions.KubeConfig),
	)
	if err != nil {
		return xerrors.Errorf("failed getting k8s cluster: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	switch args[0] {
	case clusterArtifact:
		return clusterRun(ctx, opts, cluster)
	case allArtifact:
		return namespaceRun(ctx, opts, cluster)
	default: // resourceArtifact
		return resourceRun(ctx, args, opts, cluster)
	}
}

type runner struct {
	flagOpts flag.Options
	cluster  string
}

func newRunner(flagOpts flag.Options, cluster string) *runner {
	return &runner{
		flagOpts,
		cluster,
	}
}

func (r *runner) run(ctx context.Context, artifacts []*artifacts.Artifact) error {
	runner, err := cmd.NewRunner(ctx, r.flagOpts)
	if err != nil {
		if errors.Is(err, cmd.SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
	}
	defer func() {
		if err := runner.Close(ctx); err != nil {
			log.Logger.Errorf("failed to close runner: %s", err)
		}
	}()
	var rpt report.Report
	if r.flagOpts.Format == rep.FormatCycloneDX {
		rpt, err = clusterInfoToReport(r.cluster, artifacts)
		if err != nil {
			return xerrors.Errorf("scanner error: %w", err)
		}
	} else {
		s := scanner.NewScanner(r.cluster, runner, r.flagOpts)

		// set scanners types by spec
		if r.flagOpts.Compliance.Spec.ID != "" {
			scanners, err := r.flagOpts.Compliance.Scanners()
			if err != nil {
				return xerrors.Errorf("scanner error: %w", err)
			}
			r.flagOpts.ScanOptions.Scanners = scanners
		}

		rpt, err = s.Scan(ctx, artifacts)
		if err != nil {
			return xerrors.Errorf("k8s scan error: %w", err)
		}

		if r.flagOpts.Compliance.Spec.ID != "" {
			var scanResults []types.Results
			for _, rss := range rpt.Resources {
				scanResults = append(scanResults, rss.Results)
			}
			complianceReport, err := cr.BuildComplianceReport(scanResults, r.flagOpts.Compliance)
			if err != nil {
				return xerrors.Errorf("compliance report build error: %w", err)
			}
			return cr.Write(complianceReport, cr.Option{
				Format: r.flagOpts.Format,
				Report: r.flagOpts.ReportFormat,
				Output: r.flagOpts.Output,
			})
		}
	}

	if err := k8sRep.Write(rpt, report.Option{
		Format:     r.flagOpts.Format,
		Report:     r.flagOpts.ReportFormat,
		Output:     r.flagOpts.Output,
		Severities: r.flagOpts.Severities,
		Components: r.flagOpts.Components,
		Scanners:   r.flagOpts.ScanOptions.Scanners,
		APIVersion: r.flagOpts.AppVersion,
	}); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	operation.Exit(r.flagOpts, rpt.Failed())

	return nil
}

// Full-cluster scanning with '--format table' without explicit '--report all' is not allowed so that it won't mess up user's terminal.
// To show all the results, user needs to specify "--report all" explicitly
// even though the default value of "--report" is "all".
//
// e.g.
// $ trivy k8s --report all cluster
// $ trivy k8s --report all all
//
// Or they can use "--format json" with implicit "--report all".
//
// e.g. $ trivy k8s --format json cluster // All the results are shown in JSON
//
// Single resource scanning is allowed with implicit "--report all".
//
// e.g. $ trivy k8s pod myapp
func validateReportArguments(opts flag.Options) error {
	if opts.ReportFormat == "all" &&
		!viper.IsSet("report") &&
		opts.Format == "table" {

		m := "All the results in the table format can mess up your terminal. Use \"--report all\" to tell Trivy to output it to your terminal anyway, or consider \"--report summary\" to show the summary output."

		return xerrors.New(m)
	}

	return nil
}

func clusterInfoToReport(clusterName string, allArtifact []*artifacts.Artifact) (report.Report, error) {
	resources := make([]report.Resource, 0)
	for _, artifact := range allArtifact {
		switch artifact.Kind {
		case "Pod":
			var comp bom.Component
			err := ms.Decode(artifact.RawResource, &comp)
			if err != nil {
				return report.Report{}, err
			}
			resources = append(resources, report.Resource{
				Kind: artifact.Kind,
				Name: comp.ID,
				Report: types.Report{
					ArtifactName: comp.ID,
					ArtifactType: ftypes.ArtifactContainerImage,
					Metadata: types.Metadata{
						RepoDigests: []string{fmt.Sprintf("%s/%s@sha256:%s", comp.Registry, comp.Repository, comp.Digest)},
					},
					Results: types.Results{
						{
							Target: "containers",
							Type:   "oci",
							Packages: ftypes.Packages{
								{
									Name:    fmt.Sprintf("%s/%s", comp.Registry, comp.Repository),
									Version: comp.Version,
								},
							},
						},
					},
				}})
		case "NodeInfo":
			var nf bom.NodeInfo
			err := ms.Decode(artifact.RawResource, &nf)
			if err != nil {
				return report.Report{}, err
			}
			metadata := types.Metadata{
				Properties: []types.Property{
					{
						Key:   "node_role",
						Value: nf.NodeRole,
					},
					{
						Key:   "host_name",
						Value: nf.Hostname,
					},
					{
						Key:   "kernel_version",
						Value: nf.KernelVersion,
					},
					{
						Key:   "operating_system",
						Value: nf.OperatingSystem,
					},
					{
						Key:   "architecture",
						Value: nf.Architecture,
					},
				},
			}
			osParts := strings.Split(nf.OsImage, " ")
			if len(osParts) == 2 {
				metadata.OS = &ftypes.OS{
					Family: strings.TrimSpace(osParts[0]),
					Name:   strings.TrimSpace(osParts[1]),
				}
			}
			resources = append(resources, report.Resource{
				Kind: "Node",
				Name: artifact.Name,
				Report: types.Report{
					ArtifactName: nf.NodeName,
					ArtifactType: ftypes.ArtifactVM,
					Metadata:     metadata,
					Results: types.Results{
						{
							Target: "os-packages",
							Class:  types.ClassOSPkg,
							Type:   "debian",
						},
						{
							Target: "core-components",
							Class:  types.ClassLangPkg,
							Type:   "golang",
							Packages: ftypes.Packages{
								{
									Name:    "containerd",
									Version: nf.ContainerRuntimeVersion,
								},
								{
									Name:    "kubelet_version",
									Version: nf.KubeletVersion,
								},
							},
						},
					},
				},
			})
		}
	}
	return report.Report{
		Resources: resources, ClusterName: clusterName, SchemaVersion: 0,
	}, nil
}
