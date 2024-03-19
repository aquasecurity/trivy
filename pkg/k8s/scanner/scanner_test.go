package scanner

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/maps"
	"sort"
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/purl"
)

func TestScanner_Scan(t *testing.T) {
	flagOpts := flag.Options{ReportOptions: flag.ReportOptions{Format: "cyclonedx"}}
	tests := []struct {
		name           string
		clusterName    string
		artifacts      []*artifacts.Artifact
		wantComponents []*core.Component
	}{
		{
			name:        "test cluster info with resources",
			clusterName: "test-cluster",
			artifacts: []*artifacts.Artifact{
				{
					Namespace: "kube-system",
					Kind:      "Cluster",
					Name:      "k8s.io/kubernetes",
					RawResource: map[string]interface{}{
						"name":    "k8s.io/kubernetes",
						"version": "1.21.1",
						"type":    "ClusterInfo",
						"Properties": map[string]string{
							"Name": "kind-kind",
							"Type": "cluster",
						},
					},
				},
				{
					Namespace: "kube-system",
					Kind:      "ControlPlaneComponents",
					Name:      "k8s.io/apiserver",
					RawResource: map[string]interface{}{
						"Containers": []interface{}{
							map[string]interface{}{
								"Digest":     "18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
								"ID":         "kube-apiserver:v1.21.1",
								"Registry":   "k8s.gcr.io",
								"Repository": "kube-apiserver",
								"Version":    "v1.21.1",
							},
						},
						"Name":    "k8s.io/apiserver",
						"Version": "1.21.1",
					},
				},
				{
					Kind: "NodeComponents",
					Name: "kind-control-plane",
					RawResource: map[string]interface{}{
						"ContainerRuntimeVersion": "containerd://1.5.2",
						"Hostname":                "kind-control-plane",
						"KubeProxyVersion":        "6.2.13-300.fc38.aarch64",
						"KubeletVersion":          "v1.21.1",
						"NodeName":                "kind-control-plane",
						"OsImage":                 "Ubuntu 21.04",
						"Properties": map[string]string{
							"Architecture":    "arm64",
							"HostName":        "kind-control-plane",
							"KernelVersion":   "6.2.15-300.fc38.aarch64",
							"NodeRole":        "master",
							"OperatingSystem": "linux",
						},
					},
				},
			},
			wantComponents: []*core.Component{
				{
					Type:    core.TypeApplication,
					Name:    "github.com/containerd/containerd",
					Version: "1.5.2",
					Properties: []core.Property{
						{
							Name:      k8sComponentName,
							Value:     "github.com/containerd/containerd",
							Namespace: k8sCoreComponentNamespace,
						},
						{
							Name:      k8sComponentType,
							Value:     "node",
							Namespace: k8sCoreComponentNamespace,
						},
					},
					PkgID: core.PkgID{
						PURL: &packageurl.PackageURL{
							Type:       "golang",
							Name:       "github.com/containerd/containerd",
							Version:    "1.5.2",
							Qualifiers: packageurl.Qualifiers{},
						},
						BOMRef: "pkg:golang/github.com%2Fcontainerd%2Fcontainerd@1.5.2",
					},
				},
				{
					Type:    core.TypeApplication,
					Name:    "k8s.io/apiserver",
					Version: "1.21.1",
					PkgID: core.PkgID{
						PURL: &packageurl.PackageURL{
							Type:    purl.TypeK8s,
							Name:    "k8s.io/apiserver",
							Version: "1.21.1",
						},
						BOMRef: "pkg:k8s/k8s.io%2Fapiserver@1.21.1",
					},
				},
				{
					Type:    core.TypeApplication,
					Name:    "k8s.io/kubelet",
					Version: "1.21.1",
					Properties: []core.Property{
						{
							Name:      k8sComponentName,
							Value:     "k8s.io/kubelet",
							Namespace: k8sCoreComponentNamespace,
						},
						{
							Name:      k8sComponentType,
							Value:     "node",
							Namespace: k8sCoreComponentNamespace,
						},
					},
					PkgID: core.PkgID{
						PURL: &packageurl.PackageURL{
							Type:    "k8s",
							Name:    "k8s.io/kubelet",
							Version: "1.21.1",
						},
						BOMRef: "pkg:k8s/k8s.io%2Fkubelet@1.21.1",
					},
				},
				{
					Type: core.TypeApplication,
					Name: "node-core-components",
					PkgID: core.PkgID{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000006",
					},
				},
				{
					Type:    core.TypeContainerImage,
					Name:    "k8s.gcr.io/kube-apiserver",
					Version: "sha256:18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
					PkgID: core.PkgID{
						PURL: &packageurl.PackageURL{
							Type:    "oci",
							Name:    "kube-apiserver",
							Version: "sha256:18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
							Qualifiers: packageurl.Qualifiers{
								{
									Key:   "repository_url",
									Value: "k8s.gcr.io/kube-apiserver",
								},
							},
						},
						BOMRef: "pkg:oci/kube-apiserver@sha256%3A18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f?repository_url=k8s.gcr.io%2Fkube-apiserver",
					},
					Properties: []core.Property{
						{
							Name:  core.PropertyPkgID,
							Value: "k8s.gcr.io/kube-apiserver:1.21.1",
						},
						{
							Name:  core.PropertyPkgType,
							Value: "oci",
						},
					},
				},
				{
					Type:    core.TypeOS,
					Name:    "ubuntu",
					Version: "21.04",
					Properties: []core.Property{
						{
							Name:      "Class",
							Value:     "os-pkgs",
							Namespace: "",
						},
						{
							Name:      "Type",
							Value:     "ubuntu",
							Namespace: "",
						},
					},
					PkgID: core.PkgID{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000005",
					},
				},
				{
					Type:    core.TypePlatform,
					Root:    true,
					Name:    "k8s.io/kubernetes",
					Version: "1.21.1",
					Properties: []core.Property{
						{
							Name:      "Name",
							Value:     "kind-kind",
							Namespace: k8sCoreComponentNamespace,
						},
						{
							Name:      "Type",
							Value:     "cluster",
							Namespace: k8sCoreComponentNamespace,
						},
					},
					PkgID: core.PkgID{
						PURL: &packageurl.PackageURL{
							Type:    purl.TypeK8s,
							Name:    "k8s.io/kubernetes",
							Version: "1.21.1",
						},
						BOMRef: "pkg:k8s/k8s.io%2Fkubernetes@1.21.1",
					},
				},
				{
					Type: core.TypePlatform,
					Name: "kind-control-plane",
					Properties: []core.Property{
						{
							Name:  "Architecture",
							Value: "arm64",
						},
						{
							Name:  "HostName",
							Value: "kind-control-plane",
						},
						{
							Name:  "KernelVersion",
							Value: "6.2.15-300.fc38.aarch64",
						},
						{
							Name:      k8sComponentName,
							Value:     "kind-control-plane",
							Namespace: k8sCoreComponentNamespace,
						},
						{
							Name:  "NodeRole",
							Value: "master",
						},
						{
							Name:  "OperatingSystem",
							Value: "linux",
						},
						{
							Name:      k8sComponentType,
							Value:     "node",
							Namespace: k8sCoreComponentNamespace,
						},
					},
					PkgID: core.PkgID{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000004",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			runner, err := cmd.NewRunner(ctx, flagOpts)
			assert.NoError(t, err)

			scanner := NewScanner(tt.clusterName, runner, flagOpts)
			got, err := scanner.Scan(ctx, tt.artifacts)
			require.NoError(t, err)

			gotComponents := maps.Values(got.BOM.Components())
			require.Equal(t, len(tt.wantComponents), len(gotComponents))

			sort.Slice(gotComponents, func(i, j int) bool {
				switch {
				case gotComponents[i].Type != gotComponents[j].Type:
					return gotComponents[i].Type < gotComponents[j].Type
				case gotComponents[i].Name != gotComponents[j].Name:
					return gotComponents[i].Name < gotComponents[j].Name
				default:
					return gotComponents[i].Version < gotComponents[j].Version
				}
			})
			for i, want := range tt.wantComponents {
				assert.EqualExportedValues(t, *want, *gotComponents[i], want.Name)
			}
		})
	}
}

func TestTestOsNameVersion(t *testing.T) {
	tests := []struct {
		name        string
		nameVersion string
		compName    string
		compVersion string
	}{

		{
			name:        "valid version",
			nameVersion: "ubuntu 20.04",
			compName:    "ubuntu",
			compVersion: "20.04",
		},
		{
			name:        "valid sem version",
			nameVersion: "ubuntu 20.04.1",
			compName:    "ubuntu",
			compVersion: "20.04.1",
		},
		{
			name:        "non valid version",
			nameVersion: "ubuntu",
			compName:    "ubuntu",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version := osNameVersion(tt.nameVersion)
			assert.Equal(t, name, tt.compName)
			assert.Equal(t, version, tt.compVersion)
		})
	}
}

func TestGeneratePURL(t *testing.T) {
	tests := []struct {
		name        string
		compName    string
		compVersion string
		nodeName    string
		want        string
	}{
		{
			name:        "native k8s component",
			compName:    "k8s.io/kubelet",
			compVersion: "1.24.10",
			nodeName:    "kind-kind",
			want:        "pkg:k8s/k8s.io%2Fkubelet@1.24.10",
		},

		{
			name:        "GKE",
			compName:    "k8s.io/kubelet",
			compVersion: "1.24.10-gke.2300",
			nodeName:    "gke-gke1796-default-pool-768cb718-sk1d",
			want:        "pkg:k8s/gke/k8s.io%2Fkubelet@1.24.10-gke.2300",
		},
		{
			name:        "AKS",
			compName:    "k8s.io/kubelet",
			compVersion: "1.24.10-hotfix.20221110",
			nodeName:    "aks-default-23814474-vmss000000",
			want:        "pkg:k8s/aks/k8s.io%2Fkubelet@1.24.10-hotfix.20221110",
		},
		{
			name:        "EKS",
			compName:    "k8s.io/kubelet",
			compVersion: "1.23.17-eks-8ccc7ba",
			nodeName:    "eks-vmss000000",
			want:        "pkg:k8s/eks/k8s.io%2Fkubelet@1.23.17-eks-8ccc7ba",
		},
		{
			name:        "Rancher",
			compName:    "k8s.io/kubelet",
			compVersion: "1.24.11+rke2r1",
			nodeName:    "ip-10-0-5-23",
			want:        "pkg:k8s/k8s.io%2Fkubelet@1.24.11%2Brke2r1",
		},
		{
			name:        "OCP",
			compName:    "k8s.io/kubelet",
			compVersion: "1.26.7+c7ee51f",
			nodeName:    "ocp413vpool14000-p8vnm-master-2",
			want:        "pkg:k8s/ocp/k8s.io%2Fkubelet@1.26.7%2Bc7ee51f",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generatePURL(tt.compName, tt.compVersion, tt.nodeName)
			assert.Equal(t, tt.want, got.String())
		})
	}
}

func TestK8sNamespace(t *testing.T) {
	tests := []struct {
		name        string
		compVersion string
		nodeName    string
		want        string
	}{
		{
			name:        "native k8s component",
			compVersion: "1.24.10",
			nodeName:    "kind-kind",
			want:        "kubernetes",
		},

		{
			name:        "GKE",
			compVersion: "1.24.10-gke.2300",
			nodeName:    "gke-gke1796-default-pool-768cb718-sk1d",
			want:        "gke",
		},
		{
			name:        "AKS",
			compVersion: "1.24.10-hotfix.20221110",
			nodeName:    "aks-default-23814474-vmss000000",
			want:        "aks",
		},
		{
			name:        "EKS",
			compVersion: "1.23.17-eks-8ccc7ba",
			nodeName:    "eks-vmss000000",
			want:        "eks",
		},
		{
			name:        "Rancher",
			compVersion: "1.24.11+rke2r1",
			nodeName:    "ip-10-0-5-23",
			want:        "kubernetes",
		},
		{
			name:        "OCP",
			compVersion: "1.26.7+c7ee51f",
			nodeName:    "ocp413vpool14000-p8vnm-master-2",
			want:        "ocp",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := k8sNamespace(tt.compVersion, tt.nodeName)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRuntimeVersion(t *testing.T) {
	tests := []struct {
		name           string
		runtimeVersion string
		wantName       string
		wantVersion    string
	}{
		{
			name:           "containerd",
			runtimeVersion: "containerd://1.5.2",
			wantName:       "github.com/containerd/containerd",
			wantVersion:    "1.5.2",
		},
		{
			name:           "cri-o",
			runtimeVersion: "cri-o://1.5.2",
			wantName:       "github.com/cri-o/cri-o",
			wantVersion:    "1.5.2",
		},
		{
			name:           "cri-dockerd",
			runtimeVersion: "cri-dockerd://1.5.2",
			wantName:       "github.com/Mirantis/cri-dockerd",
			wantVersion:    "1.5.2",
		},
		{
			name:           "na runtime",
			runtimeVersion: "cri:1.5.2",
			wantName:       "",
			wantVersion:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion := runtimeNameVersion(tt.runtimeVersion)
			assert.Equal(t, tt.wantName, gotName)
			assert.Equal(t, tt.wantVersion, gotVersion)
		})
	}
}

func TestFindNodeName(t *testing.T) {
	tests := []struct {
		name      string
		artifacts []*artifacts.Artifact
		want      string
	}{
		{
			name: "find node name",
			artifacts: []*artifacts.Artifact{
				{
					Namespace:   "kube-system",
					Kind:        "Cluster",
					Name:        "k8s.io/kubernetes",
					RawResource: map[string]interface{}{},
				},
				{
					Namespace:   "kube-system",
					Kind:        "ControlPlaneComponents",
					Name:        "k8s.io/apiserver",
					RawResource: map[string]interface{}{},
				},
				{
					Kind:        "NodeComponents",
					Name:        "kind-control-plane",
					RawResource: map[string]interface{}{},
				},
			},
			want: "kind-control-plane",
		},
		{
			name: "didn't find node name",
			artifacts: []*artifacts.Artifact{
				{
					Namespace:   "kube-system",
					Kind:        "Cluster",
					Name:        "k8s.io/kubernetes",
					RawResource: map[string]interface{}{},
				},
				{
					Namespace:   "kube-system",
					Kind:        "ControlPlaneComponents",
					Name:        "k8s.io/apiserver",
					RawResource: map[string]interface{}{},
				},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{}
			got := s.findNodeName(tt.artifacts)
			assert.Equal(t, tt.want, got)
		})
	}
}
