package core_test

import (
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx/core"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

func TestMarshaler_CoreComponent(t *testing.T) {
	noDepRefs := []string{}
	tests := []struct {
		name          string
		rootComponent *core.Component
		want          *cdx.BOM
	}{
		{
			name: "marshal CoreComponent",
			rootComponent: &core.Component{
				Type: cdx.ComponentTypeContainer,
				Name: "test-cluster",
				Components: []*core.Component{
					{
						Type: cdx.ComponentTypeApplication,
						Name: "kube-apiserver-kind-control-plane",
						Properties: []core.Property{
							{
								Name:  "control_plane_components",
								Value: "kube-apiserver",
							},
						},
						Components: []*core.Component{
							{
								Type:    cdx.ComponentTypeContainer,
								Name:    "k8s.gcr.io/kube-apiserver",
								Version: "sha256:18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
								PackageURL: &purl.PackageURL{
									PackageURL: packageurl.PackageURL{
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
								},
								Hashes: []digest.Digest{"sha256:18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f"},
								Properties: []core.Property{
									{
										Name:  "PkgID",
										Value: "k8s.gcr.io/kube-apiserver:1.21.1",
									},
									{
										Name:  "PkgType",
										Value: "oci",
									},
								},
							},
						},
					},
					{
						Type: cdx.ComponentTypeContainer,
						Name: "kind-control-plane",
						Properties: []core.Property{
							{
								Name:  "architecture",
								Value: "arm64",
							},
							{
								Name:  "host_name",
								Value: "kind-control-plane",
							},
							{
								Name:  "kernel_version",
								Value: "6.2.13-300.fc38.aarch64",
							},
							{
								Name:  "node_role",
								Value: "master",
							},
							{
								Name:  "operating_system",
								Value: "linux",
							},
						},
						Components: []*core.Component{
							{
								Type:    cdx.ComponentTypeOS,
								Name:    "ubuntu",
								Version: "21.04",
								Properties: []core.Property{
									{
										Name:  "Class",
										Value: "os-pkgs",
									},
									{
										Name:  "Type",
										Value: "ubuntu",
									},
								},
							},
							{
								Type: cdx.ComponentTypeApplication,
								Name: "node-core-components",
								Properties: []core.Property{
									{
										Name:  "Class",
										Value: "lang-pkgs",
									},
									{
										Name:  "Type",
										Value: "golang",
									},
								},
								Components: []*core.Component{
									{
										Type:    cdx.ComponentTypeLibrary,
										Name:    "kubelet",
										Version: "1.21.1",
										Properties: []core.Property{
											{
												Name:  "PkgType",
												Value: "golang",
											},
										},
										PackageURL: &purl.PackageURL{
											PackageURL: packageurl.PackageURL{
												Type:       "golang",
												Name:       "kubelet",
												Version:    "1.21.1",
												Qualifiers: packageurl.Qualifiers{},
											},
										},
									},
									{
										Type:    cdx.ComponentTypeLibrary,
										Name:    "containerd",
										Version: "1.5.2",
										Properties: []core.Property{
											{
												Name:  "PkgType",
												Value: "golang",
											},
										},
										PackageURL: &purl.PackageURL{
											PackageURL: packageurl.PackageURL{
												Type:       "golang",
												Name:       "containerd",
												Version:    "1.5.2",
												Qualifiers: packageurl.Qualifiers{},
											},
										},
									},
								},
							},
						},
					},
				},
			},

			want: &cdx.BOM{
				XMLNS:        "http://cyclonedx.org/schema/bom/1.5",
				BOMFormat:    "CycloneDX",
				SerialNumber: "urn:uuid:3ff14136-e09f-4df9-80ea-000000000001",
				JSONSchema:   "http://cyclonedx.org/schema/bom-1.5.schema.json",
				SpecVersion:  cdx.SpecVersion1_5,
				Version:      1,
				Metadata: &cdx.Metadata{
					Timestamp: "2021-08-25T12:20:30+00:00",
					Tools: &[]cdx.Tool{
						{
							Name:    "trivy",
							Vendor:  "aquasecurity",
							Version: "dev",
						},
					},
					Component: &cdx.Component{
						BOMRef:     "3ff14136-e09f-4df9-80ea-000000000002",
						Name:       "test-cluster",
						Properties: &[]cdx.Property{},
						Type:       cdx.ComponentTypeContainer,
					},
				},
				Vulnerabilities: &[]cdx.Vulnerability{},
				Components: &[]cdx.Component{
					{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000003",
						Type:   "application",
						Name:   "kube-apiserver-kind-control-plane",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:control_plane_components",
								Value: "kube-apiserver",
							},
						},
					},
					{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000004",
						Type:   "container",
						Name:   "kind-control-plane",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:architecture",
								Value: "arm64",
							},
							{
								Name:  "aquasecurity:trivy:host_name",
								Value: "kind-control-plane",
							},
							{
								Name:  "aquasecurity:trivy:kernel_version",
								Value: "6.2.13-300.fc38.aarch64",
							},
							{
								Name:  "aquasecurity:trivy:node_role",
								Value: "master",
							},
							{
								Name:  "aquasecurity:trivy:operating_system",
								Value: "linux",
							},
						},
					},
					{
						BOMRef:  "3ff14136-e09f-4df9-80ea-000000000005",
						Type:    "operating-system",
						Name:    "ubuntu",
						Version: "21.04",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "os-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "ubuntu",
							},
						},
					},
					{
						BOMRef: "3ff14136-e09f-4df9-80ea-000000000006",
						Type:   "application",
						Name:   "node-core-components",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:Class",
								Value: "lang-pkgs",
							},
							{
								Name:  "aquasecurity:trivy:Type",
								Value: "golang",
							},
						},
					},
					{
						BOMRef:     "pkg:golang/containerd@1.5.2",
						Type:       "library",
						Name:       "containerd",
						Version:    "1.5.2",
						PackageURL: "pkg:golang/containerd@1.5.2",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "golang",
							},
						},
					},
					{
						BOMRef:     "pkg:golang/kubelet@1.21.1",
						Type:       "library",
						Name:       "kubelet",
						Version:    "1.21.1",
						PackageURL: "pkg:golang/kubelet@1.21.1",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "golang",
							},
						},
					},
					{
						BOMRef: "pkg:oci/kube-apiserver@sha256%3A18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f?arch=&repository_url=k8s.gcr.io%2Fkube-apiserver",
						Hashes: &[]cdx.Hash{
							{
								Algorithm: "SHA-256",
								Value:     "18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
							},
						},
						Type:       "container",
						Name:       "k8s.gcr.io/kube-apiserver",
						Version:    "sha256:18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f",
						PackageURL: "pkg:oci/kube-apiserver@sha256%3A18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f?arch=&repository_url=k8s.gcr.io%2Fkube-apiserver",
						Properties: &[]cdx.Property{
							{
								Name:  "aquasecurity:trivy:PkgID",
								Value: "k8s.gcr.io/kube-apiserver:1.21.1",
							},
							{
								Name:  "aquasecurity:trivy:PkgType",
								Value: "oci",
							},
						},
					},
				},
				Dependencies: &[]cdx.Dependency{
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000002",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000003",
							"3ff14136-e09f-4df9-80ea-000000000004",
						},
					},
					{
						Ref:          "3ff14136-e09f-4df9-80ea-000000000003",
						Dependencies: &[]string{"pkg:oci/kube-apiserver@sha256%3A18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f?arch=&repository_url=k8s.gcr.io%2Fkube-apiserver"},
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000004",
						Dependencies: &[]string{
							"3ff14136-e09f-4df9-80ea-000000000005",
							"3ff14136-e09f-4df9-80ea-000000000006",
						},
					},
					{
						Ref:          "3ff14136-e09f-4df9-80ea-000000000005",
						Dependencies: &noDepRefs,
					},
					{
						Ref: "3ff14136-e09f-4df9-80ea-000000000006",
						Dependencies: &[]string{
							"pkg:golang/containerd@1.5.2",
							"pkg:golang/kubelet@1.21.1",
						},
					},
					{
						Ref:          "pkg:golang/containerd@1.5.2",
						Dependencies: &noDepRefs,
					},
					{
						Ref:          "pkg:golang/kubelet@1.21.1",
						Dependencies: &noDepRefs,
					},
					{
						Ref:          "pkg:oci/kube-apiserver@sha256%3A18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f?arch=&repository_url=k8s.gcr.io%2Fkube-apiserver",
						Dependencies: &noDepRefs,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock.SetFakeTime(t, time.Date(2021, 8, 25, 12, 20, 30, 5, time.UTC))
			uuid.SetFakeUUID(t, "3ff14136-e09f-4df9-80ea-%012d")

			marshaler := core.NewCycloneDX("dev")
			got := marshaler.Marshal(tt.rootComponent)
			assert.Equal(t, tt.want, got)
		})
	}
}
