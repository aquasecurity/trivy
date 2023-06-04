package scanner

import (
	"context"
	"sort"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/package-url/packageurl-go"

	"github.com/aquasecurity/trivy/pkg/flag"

	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx/core"

	"github.com/stretchr/testify/assert"
)

func TestK8sClusterInfoReport(t *testing.T) {
	flagOpts := flag.Options{ReportOptions: flag.ReportOptions{Format: "cyclonedx"}}
	tests := []struct {
		name        string
		clusterName string
		artifacts   []*artifacts.Artifact
		want        *core.Component
	}{
		{
			name:        "test cluster info with resources",
			clusterName: "test-cluster",
			artifacts: []*artifacts.Artifact{
				{
					Namespace: "kube-system",
					Kind:      "PodInfo",
					Name:      "kube-apiserver-kind-control-plane",
					RawResource: map[string]interface{}{
						"Containers": []interface{}{map[string]interface{}{
							"Digest":     "18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
							"ID":         "kube-apiserver:v1.21.1",
							"Registry":   "k8s.gcr.io",
							"Repository": "kube-apiserver",
							"Version":    "v1.21.1",
						},
						},
						"Name":      "kube-apiserver-kind-control-plane",
						"Namespace": "kube-system",
					},
				},
				{
					Kind: "NodeInfo",
					Name: "kind-control-plane",
					RawResource: map[string]interface{}{
						"Architecture":            "arm64",
						"ContainerRuntimeVersion": "containerd://1.5.2",
						"Hostname":                "kind-control-plane",
						"KernelVersion":           "6.2.13-300.fc38.aarch64",
						"KubeProxyVersion":        "6.2.13-300.fc38.aarch64",
						"KubeletVersion":          "v1.21.1",
						"NodeName":                "kind-control-plane",
						"NodeRole":                "master",
						"OperatingSystem":         "linux",
						"OsImage":                 "Ubuntu 21.04",
					},
				},
			},
			want: &core.Component{
				Type: cdx.ComponentTypeContainer,
				Name: "test-cluster",
				Components: []*core.Component{
					{
						Type: cdx.ComponentTypeApplication,
						Name: "kube-apiserver-kind-control-plane",
						Properties: map[string]string{
							"SchemaVersion": "0",
						},
						Components: []*core.Component{
							{
								Type:    cdx.ComponentTypeContainer,
								Name:    "k8s.gcr.io/kube-apiserver",
								Version: "sha256:18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
								PackageURL: &purl.PackageURL{
									packageurl.PackageURL{
										Type:    "oci",
										Name:    "kube-apiserver",
										Version: "sha256:18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
										Qualifiers: packageurl.Qualifiers{
											{
												Key:   "repository_url",
												Value: "k8s.gcr.io/kube-apiserver",
											},
											{
												Key: "arch",
											},
										},
									},
									"",
								},
								Hashes: []digest.Digest{"sha256:18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f"},
								Properties: map[string]string{
									"PkgID":   "k8s.gcr.io/kube-apiserver:1.21.1",
									"PkgType": "oci",
								},
							},
						},
					},
					{
						Type: cdx.ComponentTypeContainer,
						Name: "kind-control-plane",
						Properties: map[string]string{
							"architecture":     "arm64",
							"host_name":        "kind-control-plane",
							"kernel_version":   "6.2.13-300.fc38.aarch64",
							"node_role":        "master",
							"operating_system": "linux",
						},
						Components: []*core.Component{
							{
								Type:    cdx.ComponentTypeOS,
								Name:    "ubuntu",
								Version: "21.04",
								Properties: map[string]string{
									"Class": "os-pkgs",
									"Type":  "ubuntu",
								},
							},
							{
								Type: cdx.ComponentTypeApplication,
								Name: "node-core-components",
								Properties: map[string]string{
									"Class": "lang-pkgs",
									"Type":  "golang",
								},
								Components: []*core.Component{
									{
										Type:    cdx.ComponentTypeLibrary,
										Name:    "kubelet",
										Version: "1.21.1",
										Properties: map[string]string{
											"PkgType": "golang",
										},
										PackageURL: &purl.PackageURL{
											packageurl.PackageURL{
												Type:       "golang",
												Name:       "kubelet",
												Version:    "1.21.1",
												Qualifiers: packageurl.Qualifiers{},
											},
											"",
										},
									},
									{
										Type:    cdx.ComponentTypeLibrary,
										Name:    "containerd",
										Version: "1.5.2",
										Properties: map[string]string{
											"PkgType": "golang",
										},
										PackageURL: &purl.PackageURL{
											packageurl.PackageURL{
												Type:       "golang",
												Name:       "containerd",
												Version:    "1.5.2",
												Qualifiers: packageurl.Qualifiers{},
											},
											"",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			runner, err := cmd.NewRunner(ctx, flagOpts)
			assert.NoError(t, err)
			scanner := NewScanner(tt.clusterName, runner, flagOpts)
			got, err := scanner.Scan(ctx, tt.artifacts)
			sortNodeComponents(got.RootComponent)
			sortNodeComponents(tt.want)
			assert.Equal(t, tt.want, got.RootComponent)
		})
	}
}

type coreComponents []*core.Component

func (a coreComponents) Len() int           { return len(a) }
func (a coreComponents) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a coreComponents) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func sortNodeComponents(component *core.Component) {
	nodeComp := findComponentByName(component, "node-core-components")
	sort.Sort(coreComponents(nodeComp.Components))
}

func findComponentByName(component *core.Component, compName string) *core.Component {
	if component.Name == compName {
		return component
	}
	var fComp *core.Component
	for _, comp := range component.Components {
		fComp = findComponentByName(comp, compName)
	}
	return fComp
}
