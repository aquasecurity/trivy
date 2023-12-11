package scanner

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
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
	cyc "github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx/core"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	k8sCoreComponentNamespace = core.Namespace + "resource:"
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
		rootComponent, err := clusterInfoToReportResources(artifactsData)
		if err != nil {
			return report.Report{}, err
		}
		return report.Report{
			SchemaVersion: 0,
			RootComponent: rootComponent,
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
	golang                 = "golang"
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
	if nodeName = findNodeName(artifactsData); nodeName == "" {
		return resources, nil
	}

	k8sScanner := k8s.NewKubenetesScanner()
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

func findNodeName(allArtifact []*artifacts.Artifact) string {
	for _, artifact := range allArtifact {
		if artifact.Kind != nodeComponents {
			continue
		}
		return artifact.Name
	}
	return ""
}

func clusterInfoToReportResources(allArtifact []*artifacts.Artifact) (*core.Component, error) {
	var coreComponents []*core.Component
	var cInfo *core.Component

	// Find the first node name to identify AKS cluster
	var nodeName string
	if nodeName = findNodeName(allArtifact); nodeName == "" {
		return nil, fmt.Errorf("failed to find node name")
	}

	for _, artifact := range allArtifact {
		switch artifact.Kind {
		case controlPlaneComponents:
			var comp bom.Component
			err := ms.Decode(artifact.RawResource, &comp)
			if err != nil {
				return nil, err
			}
			var imageComponents []*core.Component
			for _, c := range comp.Containers {
				name := fmt.Sprintf("%s/%s", c.Registry, c.Repository)
				cDigest := c.Digest
				if !strings.Contains(c.Digest, string(digest.SHA256)) {
					cDigest = fmt.Sprintf("%s:%s", string(digest.SHA256), cDigest)
				}
				ver := sanitizedVersion(c.Version)

				imagePURL, err := purl.NewPackageURL(purl.TypeOCI, types.Metadata{
					RepoDigests: []string{
						fmt.Sprintf("%s@%s", name, cDigest),
					},
				}, ftypes.Package{})

				if err != nil {
					return nil, xerrors.Errorf("failed to create PURL: %w", err)
				}
				imageComponents = append(imageComponents, &core.Component{
					PackageURL: imagePURL,
					Type:       cdx.ComponentTypeContainer,
					Name:       name,
					Version:    cDigest,
					Properties: []core.Property{
						{
							Name:  cyc.PropertyPkgID,
							Value: fmt.Sprintf("%s:%s", name, ver),
						},
						{
							Name:  cyc.PropertyPkgType,
							Value: oci,
						},
					},
				})
			}
			rootComponent := &core.Component{
				Name:       comp.Name,
				Version:    comp.Version,
				Type:       cdx.ComponentTypeApplication,
				Properties: toProperties(comp.Properties, k8sCoreComponentNamespace),
				Components: imageComponents,
				PackageURL: generatePURL(comp.Name, comp.Version, nodeName),
			}
			coreComponents = append(coreComponents, rootComponent)
		case nodeComponents:
			var nf bom.NodeInfo
			err := ms.Decode(artifact.RawResource, &nf)
			if err != nil {
				return nil, err
			}
			coreComponents = append(coreComponents, nodeComponent(nf))
		case clusterInfo:
			var cf bom.ClusterInfo
			err := ms.Decode(artifact.RawResource, &cf)
			if err != nil {
				return nil, err
			}
			cInfo = &core.Component{
				Name:       cf.Name,
				Version:    cf.Version,
				Properties: toProperties(cf.Properties, k8sCoreComponentNamespace),
			}
		default:
			return nil, fmt.Errorf("resource kind %s is not supported", artifact.Kind)
		}
	}
	rootComponent := &core.Component{
		Name:       cInfo.Name,
		Version:    cInfo.Version,
		Type:       cdx.ComponentTypePlatform,
		Properties: cInfo.Properties,
		Components: coreComponents,
		PackageURL: generatePURL(cInfo.Name, cInfo.Version, nodeName),
	}
	return rootComponent, nil
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

func nodeComponent(nf bom.NodeInfo) *core.Component {
	osName, osVersion := osNameVersion(nf.OsImage)
	runtimeName, runtimeVersion := runtimeNameVersion(nf.ContainerRuntimeVersion)
	kubeletVersion := sanitizedVersion(nf.KubeletVersion)
	properties := toProperties(nf.Properties, "")
	properties = append(properties, toProperties(map[string]string{
		k8sComponentType: k8sComponentNode,
		k8sComponentName: nf.NodeName,
	}, k8sCoreComponentNamespace)...)
	return &core.Component{
		Type:       cdx.ComponentTypePlatform,
		Name:       nf.NodeName,
		Properties: properties,
		Components: []*core.Component{
			{
				Type:    cdx.ComponentTypeOS,
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
			},
			{
				Type: cdx.ComponentTypeApplication,
				Name: nodeCoreComponents,
				Properties: []core.Property{
					{
						Name:  "Class",
						Value: string(types.ClassLangPkg),
					},
					{
						Name:  "Type",
						Value: golang,
					},
				},
				Components: []*core.Component{
					{
						Type:    cdx.ComponentTypeApplication,
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
						PackageURL: generatePURL(kubelet, kubeletVersion, nf.NodeName),
					},
					{
						Type:    cdx.ComponentTypeApplication,
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
						PackageURL: &purl.PackageURL{
							PackageURL: *packageurl.NewPackageURL(golang, "", runtimeName, runtimeVersion, packageurl.Qualifiers{}, ""),
						},
					},
				},
			},
		},
	}
}

func toProperties(props map[string]string, namespace string) []core.Property {
	properties := lo.MapToSlice(props, func(k, v string) core.Property {
		return core.Property{
			Name:      k,
			Value:     v,
			Namespace: namespace,
		}
	})
	sort.Slice(properties, func(i, j int) bool {
		return properties[i].Name < properties[j].Name
	})
	return properties
}

func generatePURL(name, ver, nodeName string) *purl.PackageURL {

	var namespace string
	// Identify k8s distribution. An empty namespace means upstream.
	if namespace = k8sNamespace(ver, nodeName); namespace == "" {
		return nil
	} else if namespace == "kubernetes" {
		namespace = ""
	}

	return &purl.PackageURL{
		PackageURL: *packageurl.NewPackageURL(purl.TypeK8s, namespace, name, ver, nil, ""),
	}
}

func k8sNamespace(ver, nodeName string) string {
	namespace := "kubernetes"
	switch {
	case strings.Contains(ver, "eks"):
		namespace = purl.NamespaceEKS
	case strings.Contains(ver, "gke"):
		namespace = purl.NamespaceGKE
	case strings.Contains(ver, "rke2"):
		namespace = purl.NamespaceRKE
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
