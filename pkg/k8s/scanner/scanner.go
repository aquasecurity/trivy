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
	k8sCoreComponentNamespace = core.Namespace + "k8s:component" + ":"
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
		rootComponent, err := clusterInfoToReportResources(artifactsData, s.cluster)
		if err != nil {
			return report.Report{}, err
		}
		return report.Report{
			SchemaVersion: 0,
			RootComponent: rootComponent,
		}, nil
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
		resources = append(resources, result.misconfig)
		return nil
	}

	p := parallel.NewPipeline(s.opts.Parallel, !s.opts.Quiet, artifactsData, onItem, onResult)
	err = p.Do(ctx)
	if err != nil {
		return report.Report{}, err
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

const (
	golang             = "golang"
	oci                = "oci"
	kubelet            = "k8s.io/kubelet"
	pod                = "PodInfo"
	nodeInfo           = "NodeInfo"
	nodeCoreComponents = "node-core-components"
)

func clusterInfoToReportResources(allArtifact []*artifacts.Artifact, clusterName string) (*core.Component, error) {
	coreComponents := make([]*core.Component, 0)
	for _, artifact := range allArtifact {
		switch artifact.Kind {
		case pod:
			var comp bom.Component
			err := ms.Decode(artifact.RawResource, &comp)
			if err != nil {
				return nil, err
			}
			imageComponents := make([]*core.Component, 0)
			for _, c := range comp.Containers {
				name := fmt.Sprintf("%s/%s", c.Registry, c.Repository)
				cDigest := c.Digest
				if strings.Index(c.Digest, string(digest.SHA256)) == -1 {
					cDigest = fmt.Sprintf("%s:%s", string(digest.SHA256), cDigest)
				}
				version := sanitizedVersion(c.Version)

				imagePURL, err := purl.NewPackageURL(purl.TypeOCI, types.Metadata{
					RepoDigests: []string{
						fmt.Sprintf("%s@%s", name, cDigest),
					},
				}, ftypes.Package{})

				if err != nil {
					return nil, xerrors.Errorf("failed to create PURL: %w", err)
				}
				imageComponents = append(imageComponents, &core.Component{
					PackageURL: &imagePURL,
					Type:       cdx.ComponentTypeContainer,
					Name:       name,
					Version:    cDigest,
					Properties: []core.Property{
						{Name: cyc.PropertyPkgID, Value: fmt.Sprintf("%s:%s", name, version)},
						{Name: cyc.PropertyPkgType, Value: oci},
					},
				})
			}
			rootComponent := &core.Component{
				Name:       comp.Name,
				Type:       cdx.ComponentTypeApplication,
				Properties: toProperties(comp.Properties, k8sCoreComponentNamespace),
				Components: imageComponents,
			}
			coreComponents = append(coreComponents, rootComponent)
		case nodeInfo:
			var nf bom.NodeInfo
			err := ms.Decode(artifact.RawResource, &nf)
			if err != nil {
				return nil, err
			}
			coreComponents = append(coreComponents, nodeComponent(nf))
		default:
			return nil, fmt.Errorf("resource kind %s is not supported", artifact.Kind)
		}
	}
	rootComponent := &core.Component{
		Name:       clusterName,
		Type:       cdx.ComponentTypePlatform,
		Components: coreComponents,
	}
	return rootComponent, nil
}

func sanitizedVersion(version string) string {
	return strings.TrimPrefix(version, "v")
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
	parts := strings.Split(name, "://")
	if len(parts) == 2 {
		name := parts[0]
		switch parts[0] {
		case "cri-o":
			name = "github.com/cri-o/cri-o"
		case "containerd":
			name = "github.com/containerd/containerd"
		case "cri-dockerd":
			name = "github.com/Mirantis/cri-dockerd"
		}
		return name, parts[1]
	}
	return "", ""
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
					{Name: "Class", Value: types.ClassOSPkg},
					{Name: "Type", Value: osName},
				},
			},
			{
				Type: cdx.ComponentTypeApplication,
				Name: nodeCoreComponents,
				Properties: []core.Property{
					{Name: "Class", Value: types.ClassLangPkg},
					{Name: "Type", Value: golang},
				},
				Components: []*core.Component{
					{
						Type:    cdx.ComponentTypeLibrary,
						Name:    kubelet,
						Version: kubeletVersion,
						Properties: []core.Property{
							{Name: k8sComponentType, Value: k8sComponentNode, Namespace: k8sCoreComponentNamespace},
							{Name: k8sComponentName, Value: kubelet, Namespace: k8sCoreComponentNamespace},
							{Name: cyc.PropertyPkgType, Value: golang},
						},
						PackageURL: &purl.PackageURL{
							PackageURL: *packageurl.NewPackageURL(golang, "", kubelet, kubeletVersion, packageurl.Qualifiers{}, ""),
						},
					},
					{
						Type:    cdx.ComponentTypeLibrary,
						Name:    runtimeName,
						Version: runtimeVersion,
						Properties: []core.Property{
							{Name: k8sComponentType, Value: k8sComponentNode, Namespace: k8sCoreComponentNamespace},
							{Name: k8sComponentName, Value: runtimeName, Namespace: k8sCoreComponentNamespace},
							{Name: cyc.PropertyPkgType, Value: golang},
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
