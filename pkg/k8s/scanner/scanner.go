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
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
	rep "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	pod                = "PodInfo"
	nodeInfo           = "NodeInfo"
	osPackages         = "os-packages"
	nodeCoreComponents = "node-core-components"
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
		resources, err = clusterInfoToReportResources(artifactsData)
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

func clusterInfoToReportResources(allArtifact []*artifacts.Artifact) ([]report.Resource, error) {
	resources := make([]report.Resource, 0)
	for _, artifact := range allArtifact {
		switch artifact.Kind {
		case pod:
			var comp bom.Component
			err := ms.Decode(artifact.RawResource, &comp)
			if err != nil {
				return []report.Resource{}, err
			}
			packages := make(ftypes.Packages, 0)
			repoDigest := make([]string, 0)
			for _, c := range comp.Containers {
				name := fmt.Sprintf("%s/%s", c.Registry, c.Repository)
				version := sanitizedVersion(c.Version)
				packages = append(packages, ftypes.Package{
					ID:      fmt.Sprintf("%s:%s", name, version),
					Name:    name,
					Version: version,
					Digest:  digest.NewDigestFromString(digest.SHA256, strings.ReplaceAll(c.Digest, "sha256:", "")),
				},
				)
			}
			resources = append(resources, report.Resource{
				Kind: artifact.Kind,
				Name: comp.Name,
				Report: types.Report{
					ArtifactName: comp.Name,
					ArtifactType: ftypes.KubernetesPod,
					Metadata: types.Metadata{
						RepoDigests: repoDigest,
					},
					Results: types.Results{
						{
							Target:   "containers",
							Type:     "oci",
							Class:    types.ClassK8sComponents,
							Packages: packages,
						},
					},
				}})
		case nodeInfo:
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
			var name, version string
			osParts := strings.Split(nf.OsImage, " ")
			if len(osParts) == 2 {
				name = strings.TrimSpace(osParts[0])
				version = strings.TrimSpace(osParts[1])
				metadata.OS = &ftypes.OS{
					Family: strings.ToLower(name),
					Name:   version,
				}
			}
			resources = append(resources, report.Resource{
				Kind: artifact.Kind,
				Name: artifact.Name,
				Report: types.Report{
					ArtifactName: nf.NodeName,
					ArtifactType: ftypes.ArtifactVM,
					Metadata:     metadata,
					Results: types.Results{
						{
							Target: osPackages,
							Class:  types.ClassOSPkg,
							Type:   strings.ToLower(name),
						},
						{
							Target: nodeCoreComponents,
							Class:  types.ClassLangPkg,
							Type:   "golang",
							Packages: ftypes.Packages{
								{
									Name:    "containerd",
									Version: strings.Replace(nf.ContainerRuntimeVersion, "containerd://", "", -1),
								},
								{
									Name:    "kubelet",
									Version: sanitizedVersion(nf.KubeletVersion),
								},
							},
						},
					},
				},
			})
		default:
			return nil, fmt.Errorf("resource kind %s is not supported", artifact.Kind)
		}
	}

	return resources, nil
}

func sanitizedVersion(version string) string {
	return strings.Replace(version, "v", "", -1)
}
