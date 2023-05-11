package scanner

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	ms "github.com/mitchellh/mapstructure"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
	rep "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner struct {
	cluster string
	runner  cmd.Runner
	opts    flag.Options
}

func NewScanner(cluster string, runner cmd.Runner, opts flag.Options) *Scanner {
	return &Scanner{
		cluster,
		runner,
		opts,
	}
}

func (s *Scanner) Scan(ctx context.Context, artifactsData []*artifacts.Artifact) (report.Report, error) {

	// disable logs before scanning
	err := log.InitLogger(s.opts.Debug, true)
	if err != nil {
		return report.Report{}, xerrors.Errorf("logger error: %w", err)
	}

	// enable log, this is done in a defer function,
	// to enable logs even when the function returns earlier
	// due to an error
	defer func() {
		err = log.InitLogger(s.opts.Debug, false)
		if err != nil {
			// we use log.Fatal here because the error was to enable the logger
			log.Fatal(xerrors.Errorf("can't enable logger error: %w", err))
		}
	}()
	var resources []report.Resource
	if s.opts.Format == rep.FormatCycloneDX {
		resources, err = clusterInfoToReport(artifactsData)
		if err != nil {
			return report.Report{}, err
		}
	} else {
		type scanResult struct {
			vulns     []report.Resource
			misconfig report.Resource
		}

	onItem := func(ctx context.Context, artifact *artifacts.Artifact) (scanResult, error) {
		scanResults := scanResult{}
		if s.opts.Scanners.AnyEnabled(types.VulnerabilityScanner, types.SecretScanner) {
			vulns, err := s.scanVulns(ctx, artifact)
			if err != nil {
				return scanResult{}, xerrors.Errorf("scanning vulnerabilities error: %w", err)
			}
			scanResults.vulns = vulns
		}
		if local.ShouldScanMisconfigOrRbac(s.opts.Scanners) {
			misconfig, err := s.scanMisconfigs(ctx, artifact)
			if err != nil {
				return scanResult{}, xerrors.Errorf("scanning misconfigurations error: %w", err)
			}
			scanResults.misconfig = misconfig
		}
		return scanResults, nil
	}

		onResult := func(result scanResult) error {
			resources = append(resources, result.vulns...)
			resources = append(resources, result.misconfig)
			return nil
		}

		p := parallel.NewPipeline(s.opts.Parallel, !s.opts.Quiet, artifactsData, onItem, onResult)
		err = p.Do(ctx)
		if err != nil {
			return report.Report{}, err
		}
	}
	return report.Report{
		SchemaVersion: 0,
		ClusterName:   s.cluster,
		Resources:     resources,
	}, nil
}

func (s *Scanner) scanVulns(ctx context.Context, artifact *artifacts.Artifact) ([]report.Resource, error) {
	resources := make([]report.Resource, 0, len(artifact.Images))

	for _, image := range artifact.Images {

		s.opts.Target = image

		imageReport, err := s.runner.ScanImage(ctx, s.opts)

		if err != nil {
			log.Logger.Warnf("failed to scan image %s: %s", image, err)
			resources = append(resources, report.CreateResource(artifact, imageReport, err))
			continue
		}

		resource, err := s.filter(ctx, imageReport, artifact)
		if err != nil {
			return nil, xerrors.Errorf("filter error: %w", err)
		}

		resources = append(resources, resource)
	}

	return resources, nil
}

func (s *Scanner) scanMisconfigs(ctx context.Context, artifact *artifacts.Artifact) (report.Resource, error) {
	configFile, err := createTempFile(artifact)
	if err != nil {
		return report.Resource{}, xerrors.Errorf("scan error: %w", err)
	}

	s.opts.Target = configFile

	configReport, err := s.runner.ScanFilesystem(ctx, s.opts)
	//remove config file after scanning
	removeFile(configFile)
	if err != nil {
		log.Logger.Debugf("failed to scan config %s/%s: %s", artifact.Kind, artifact.Name, err)
		return report.CreateResource(artifact, configReport, err), err
	}

	return s.filter(ctx, configReport, artifact)
}
func (s *Scanner) filter(ctx context.Context, r types.Report, artifact *artifacts.Artifact) (report.Resource, error) {
	var err error
	r, err = s.runner.Filter(ctx, s.opts, r)
	if err != nil {
		return report.Resource{}, xerrors.Errorf("filter error: %w", err)
	}
	return report.CreateResource(artifact, r, nil), nil
}

func clusterInfoToReport(allArtifact []*artifacts.Artifact) ([]report.Resource, error) {
	resources := make([]report.Resource, 0)
	for _, artifact := range allArtifact {
		switch artifact.Kind {
		case "Pod":
			var comp bom.Component
			err := ms.Decode(artifact.RawResource, &comp)
			if err != nil {
				return []report.Resource{}, err
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
				return []report.Resource{}, err
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

	return resources, nil
}
