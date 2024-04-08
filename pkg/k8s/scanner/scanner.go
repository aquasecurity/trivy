package scanner

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	ms "github.com/mitchellh/mapstructure"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/bom"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/k8s"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	k8sCoreComponentNamespace = cyclonedx.Namespace + "resource:"
	k8sComponentType          = "Type"
	k8sComponentName          = "Name"
	k8sComponentNode          = "node"
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

	if s.opts.Format == types.FormatCycloneDX {
		kbom, err := s.clusterInfoToReportResources(artifactsData)
		if err != nil {
			return report.Report{}, err
		}
		return report.Report{
			SchemaVersion: 0,
			BOM:           kbom,
		}, nil
	}
	var resourceArtifacts []*artifacts.Artifact
	var k8sCoreArtifacts []*artifacts.Artifact
	for _, artifact := range artifactsData {
		if strings.HasSuffix(artifact.Kind, "Components") || strings.HasSuffix(artifact.Kind, "Cluster") {
			k8sCoreArtifacts = append(k8sCoreArtifacts, artifact)
			continue
		}
		resourceArtifacts = append(resourceArtifacts, artifact)
	}

	var resources []report.Resource

	type scanResult struct {
		vulns     []report.Resource
		misconfig report.Resource
	}

	onItem := func(ctx context.Context, artifact *artifacts.Artifact) (scanResult, error) {
		scanResults := scanResult{}
		if s.opts.Scanners.AnyEnabled(types.VulnerabilityScanner, types.SecretScanner) {
			opts := s.opts
			opts.Credentials = make([]ftypes.Credential, len(s.opts.Credentials))
			copy(opts.Credentials, s.opts.Credentials)
			// add image private registry credential auto detected from workload imagePullsecret / serviceAccount
			if len(artifact.Credentials) > 0 {
				for _, cred := range artifact.Credentials {
					opts.RegistryOptions.Credentials = append(opts.RegistryOptions.Credentials,
						ftypes.Credential{
							Username: cred.Username,
							Password: cred.Password,
						},
					)
				}
			}
			vulns, err := s.scanVulns(ctx, artifact, opts)
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
		// don't add empty misconfig results to resources slice to avoid an empty resource
		if result.misconfig.Results != nil {
			resources = append(resources, result.misconfig)
		}
		return nil
	}

	p := parallel.NewPipeline(s.opts.Parallel, !s.opts.Quiet, resourceArtifacts, onItem, onResult)
	err = p.Do(ctx)
	if err != nil {
		return report.Report{}, err
	}
	if s.opts.Scanners.AnyEnabled(types.VulnerabilityScanner) {
		k8sResource, err := s.scanK8sVulns(ctx, k8sCoreArtifacts)
		if err != nil {
			return report.Report{}, err
		}
		resources = append(resources, k8sResource...)
	}
	return report.Report{
		SchemaVersion: 0,
		ClusterName:   s.cluster,
		Resources:     resources,
	}, nil

}

func (s *Scanner) scanVulns(ctx context.Context, artifact *artifacts.Artifact, opts flag.Options) ([]report.Resource, error) {
	resources := make([]report.Resource, 0, len(artifact.Images))

	for _, image := range artifact.Images {

		opts.Target = image

		imageReport, err := s.runner.ScanImage(ctx, opts)

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
	// remove config file after scanning
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

const (
	oci                    = "oci"
	kubelet                = "k8s.io/kubelet"
	controlPlaneComponents = "ControlPlaneComponents"
	clusterInfo            = "Cluster"
	nodeComponents         = "NodeComponents"
	nodeCoreComponents     = "node-core-components"
)

func (s *Scanner) scanK8sVulns(ctx context.Context, artifactsData []*artifacts.Artifact) ([]report.Resource, error) {
	var resources []report.Resource
	var nodeName string
	if nodeName = s.findNodeName(artifactsData); nodeName == "" {
		return resources, nil
	}

	k8sScanner := k8s.NewKubernetesScanner()
	scanOptions := types.ScanOptions{
		Scanners: s.opts.Scanners,
		VulnType: s.opts.VulnType,
	}
	for _, artifact := range artifactsData {
		switch artifact.Kind {
		case controlPlaneComponents:
			var comp bom.Component
			err := ms.Decode(artifact.RawResource, &comp)
			if err != nil {
				return nil, err
			}

			lang := k8sNamespace(comp.Version, nodeName)
			results, _, err := k8sScanner.Scan(ctx, types.ScanTarget{
				Applications: []ftypes.Application{
					{
						Type:     ftypes.LangType(lang),
						FilePath: artifact.Name,
						Libraries: []ftypes.Package{
							{
								Name:    comp.Name,
								Version: comp.Version,
							},
						},
					},
				},
			}, scanOptions)
			if err != nil {
				return nil, err
			}
			if results != nil {
				resource, err := s.filter(ctx, types.Report{
					Results:      results,
					ArtifactName: artifact.Name,
				}, artifact)
				if err != nil {
					return nil, err
				}
				resources = append(resources, resource)
			}
		case nodeComponents:
			var nf bom.NodeInfo
			err := ms.Decode(artifact.RawResource, &nf)
			if err != nil {
				return nil, err
			}
			kubeletVersion := sanitizedVersion(nf.KubeletVersion)
			lang := k8sNamespace(kubeletVersion, nodeName)
			runtimeName, runtimeVersion := runtimeNameVersion(nf.ContainerRuntimeVersion)
			results, _, err := k8sScanner.Scan(ctx, types.ScanTarget{
				Applications: []ftypes.Application{
					{
						Type:     ftypes.LangType(lang),
						FilePath: artifact.Name,
						Libraries: []ftypes.Package{
							{
								Name:    kubelet,
								Version: kubeletVersion,
							},
						},
					},
					{
						Type:     ftypes.GoBinary,
						FilePath: artifact.Name,
						Libraries: []ftypes.Package{
							{
								Name:    runtimeName,
								Version: runtimeVersion,
							},
						},
					},
				},
			}, scanOptions)
			if err != nil {
				return nil, err
			}
			if results != nil {
				resource, err := s.filter(ctx, types.Report{
					Results:      results,
					ArtifactName: artifact.Name,
				}, artifact)
				if err != nil {
					return nil, err
				}
				resources = append(resources, resource)
			}
		case clusterInfo:
			var cf bom.ClusterInfo
			err := ms.Decode(artifact.RawResource, &cf)
			if err != nil {
				return nil, err
			}
			lang := k8sNamespace(cf.Version, nodeName)

			results, _, err := k8sScanner.Scan(ctx, types.ScanTarget{
				Applications: []ftypes.Application{
					{
						Type:     ftypes.LangType(lang),
						FilePath: artifact.Name,
						Libraries: []ftypes.Package{
							{
								Name:    cf.Name,
								Version: cf.Version,
							},
						},
					},
				},
			}, scanOptions)
			if err != nil {
				return nil, err
			}
			if results != nil {
				resource, err := s.filter(ctx, types.Report{
					Results:      results,
					ArtifactName: artifact.Name,
				}, artifact)
				if err != nil {
					return nil, err
				}
				resources = append(resources, resource)
			}
		}
	}
	return resources, nil
}

func (*Scanner) findNodeName(allArtifact []*artifacts.Artifact) string {
	for _, artifact := range allArtifact {
		if artifact.Kind != nodeComponents {
			continue
		}
		return artifact.Name
	}
	return ""
}

func (s *Scanner) clusterInfoToReportResources(allArtifact []*artifacts.Artifact) (*core.BOM, error) {
	var rootComponent *core.Component
	var coreComponents []*core.Component

	// Find the first node name to identify AKS cluster
	var nodeName string
	if nodeName = s.findNodeName(allArtifact); nodeName == "" {
		return nil, fmt.Errorf("failed to find node name")
	}

	kbom := core.NewBOM(core.Options{
		GenerateBOMRef: true,
	})
	for _, artifact := range allArtifact {
		switch artifact.Kind {
		case controlPlaneComponents:
			var comp bom.Component
			if err := ms.Decode(artifact.RawResource, &comp); err != nil {
				return nil, err
			}

			controlPlane := &core.Component{
				Name:       comp.Name,
				Version:    comp.Version,
				Type:       core.TypeApplication,
				Properties: toProperties(comp.Properties, k8sCoreComponentNamespace),
				PkgID: core.PkgID{
					PURL: generatePURL(comp.Name, comp.Version, nodeName),
				},
			}
			coreComponents = append(coreComponents, controlPlane)

			for _, c := range comp.Containers {
				name := fmt.Sprintf("%s/%s", c.Registry, c.Repository)
				cDigest := c.Digest
				if !strings.Contains(c.Digest, string(digest.SHA256)) {
					cDigest = fmt.Sprintf("%s:%s", string(digest.SHA256), cDigest)
				}
				ver := sanitizedVersion(c.Version)

				imagePURL, err := purl.New(purl.TypeOCI, types.Metadata{
					RepoDigests: []string{
						fmt.Sprintf("%s@%s", name, cDigest),
					},
				}, ftypes.Package{})
				if err != nil {
					return nil, xerrors.Errorf("failed to create PURL: %w", err)
				}

				imageComponent := &core.Component{
					Type:    core.TypeContainerImage,
					Name:    name,
					Version: cDigest,
					PkgID: core.PkgID{
						PURL: imagePURL.Unwrap(),
					},
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: fmt.Sprintf("%s:%s", name, ver),
						},
						{
							Name:  core.PropertyPkgType,
							Value: oci,
						},
					},
				}
				kbom.AddRelationship(controlPlane, imageComponent, core.RelationshipDependsOn)
			}
		case nodeComponents:
			var nf bom.NodeInfo
			err := ms.Decode(artifact.RawResource, &nf)
			if err != nil {
				return nil, err
			}
			coreComponents = append(coreComponents, s.nodeComponent(kbom, nf))
		case clusterInfo:
			var cf bom.ClusterInfo
			if err := ms.Decode(artifact.RawResource, &cf); err != nil {
				return nil, err
			}
			rootComponent = &core.Component{
				Type:       core.TypePlatform,
				Name:       cf.Name,
				Version:    cf.Version,
				Properties: toProperties(cf.Properties, k8sCoreComponentNamespace),
				PkgID: core.PkgID{
					PURL: generatePURL(cf.Name, cf.Version, nodeName),
				},
				Root: true,
			}
			kbom.AddComponent(rootComponent)
		default:
			return nil, fmt.Errorf("resource kind %s is not supported", artifact.Kind)
		}
	}

	for _, c := range coreComponents {
		kbom.AddRelationship(rootComponent, c, core.RelationshipContains)
	}

	return kbom, nil
}

func (s *Scanner) nodeComponent(b *core.BOM, nf bom.NodeInfo) *core.Component {
	osName, osVersion := osNameVersion(nf.OsImage)
	runtimeName, runtimeVersion := runtimeNameVersion(nf.ContainerRuntimeVersion)
	kubeletVersion := sanitizedVersion(nf.KubeletVersion)
	properties := toProperties(nf.Properties, "")
	properties = append(properties, toProperties(map[string]string{
		k8sComponentType: k8sComponentNode,
		k8sComponentName: nf.NodeName,
	}, k8sCoreComponentNamespace)...)

	nodeComponent := &core.Component{
		Type:       core.TypePlatform,
		Name:       nf.NodeName,
		Properties: properties,
	}

	osComponent := &core.Component{
		Type:    core.TypeOS,
		Name:    osName,
		Version: osVersion,
		Properties: []core.Property{
			{
				Name:  "Class",
				Value: string(types.ClassOSPkg),
			},
			{
				Name:  "Type",
				Value: osName,
			},
		},
	}
	b.AddRelationship(nodeComponent, osComponent, core.RelationshipContains)

	appComponent := &core.Component{
		Type: core.TypeApplication,
		Name: nodeCoreComponents,
	}
	b.AddRelationship(nodeComponent, appComponent, core.RelationshipContains)

	kubeletComponent := &core.Component{
		Type:    core.TypeApplication,
		Name:    kubelet,
		Version: kubeletVersion,
		Properties: []core.Property{
			{
				Name:      k8sComponentType,
				Value:     k8sComponentNode,
				Namespace: k8sCoreComponentNamespace,
			},
			{
				Name:      k8sComponentName,
				Value:     kubelet,
				Namespace: k8sCoreComponentNamespace,
			},
		},
		PkgID: core.PkgID{
			PURL: generatePURL(kubelet, kubeletVersion, nf.NodeName),
		},
	}
	b.AddRelationship(appComponent, kubeletComponent, core.RelationshipContains)

	runtimeComponent := &core.Component{
		Type:    core.TypeApplication,
		Name:    runtimeName,
		Version: runtimeVersion,
		Properties: []core.Property{
			{
				Name:      k8sComponentType,
				Value:     k8sComponentNode,
				Namespace: k8sCoreComponentNamespace,
			},
			{
				Name:      k8sComponentName,
				Value:     runtimeName,
				Namespace: k8sCoreComponentNamespace,
			},
		},
		PkgID: core.PkgID{
			PURL: packageurl.NewPackageURL(packageurl.TypeGolang, "", runtimeName, runtimeVersion, packageurl.Qualifiers{}, ""),
		},
	}
	b.AddRelationship(appComponent, runtimeComponent, core.RelationshipContains)

	return nodeComponent
}

func sanitizedVersion(ver string) string {
	return strings.TrimPrefix(ver, "v")
}

func osNameVersion(name string) (string, string) {
	var buffer bytes.Buffer
	var v string
	var err error
	parts := strings.Split(name, " ")
	for _, p := range parts {
		_, err = version.Parse(p)
		if err != nil {
			buffer.WriteString(p + " ")
			continue
		}
		v = p
		break
	}
	return strings.ToLower(strings.TrimSpace(buffer.String())), v
}

func runtimeNameVersion(name string) (string, string) {
	runtime, ver, ok := strings.Cut(name, "://")
	if !ok {
		return "", ""
	}

	switch runtime {
	case "cri-o":
		name = "github.com/cri-o/cri-o"
	case "containerd":
		name = "github.com/containerd/containerd"
	case "cri-dockerd":
		name = "github.com/Mirantis/cri-dockerd"
	}
	return name, ver
}

func toProperties(props map[string]string, namespace string) []core.Property {
	properties := lo.MapToSlice(props, func(k, v string) core.Property {
		return core.Property{
			Name:      k,
			Value:     v,
			Namespace: namespace,
		}
	})
	if len(properties) == 0 {
		return nil
	}
	sort.Slice(properties, func(i, j int) bool {
		return properties[i].Name < properties[j].Name
	})
	return properties
}

func generatePURL(name, ver, nodeName string) *packageurl.PackageURL {
	var namespace string
	// Identify k8s distribution. An empty namespace means upstream.
	if namespace = k8sNamespace(ver, nodeName); namespace == "" {
		return nil
	} else if namespace == "kubernetes" {
		namespace = ""
	}

	return packageurl.NewPackageURL(purl.TypeK8s, namespace, name, ver, nil, "")
}

func k8sNamespace(ver, nodeName string) string {
	namespace := "kubernetes"
	switch {
	case strings.Contains(ver, "eks"):
		namespace = purl.NamespaceEKS
	case strings.Contains(ver, "gke"):
		namespace = purl.NamespaceGKE
	case strings.Contains(ver, "hotfix"):
		if !strings.Contains(nodeName, "aks") {
			// Unknown k8s distribution
			return ""
		}
		namespace = purl.NamespaceAKS
	case strings.Contains(nodeName, "ocp"):
		namespace = purl.NamespaceOCP
	}
	return namespace
}
