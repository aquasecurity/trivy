package scanner

import (
	"context"
	"testing"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	k8s "github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestK8sClusterInfoReport(t *testing.T) {
	flagOpts := flag.Options{ReportOptions: flag.ReportOptions{Format: "cyclonedx"}}
	tests := []struct {
		name        string
		clusterName string
		artifacts   []*artifacts.Artifact
		want        report.Report
	}{
		{
			name:        "test custer info with resources",
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
			want: report.Report{
				ClusterName: "test-cluster",
				Resources: []k8s.Resource{
					{
						Kind: "PodInfo",
						Name: "kube-apiserver-kind-control-plane",
						Report: types.Report{
							ArtifactType: "k8s_pod",
							ArtifactName: "kube-apiserver-kind-control-plane",
							Metadata: types.Metadata{
								RepoDigests: []string{},
							},
							Results: types.Results{
								{
									Target: "containers",
									Type:   "oci",
									Class:  types.ClassK8sComponents,
									Packages: ftypes.Packages{
										{
											ID:      "k8s.gcr.io/kube-apiserver:1.21.1",
											Name:    "k8s.gcr.io/kube-apiserver",
											Version: "1.21.1",
											Digest:  digest.NewDigestFromString("sha256", "18e61c783b41758dd391ab901366ec3546b26fae00eef7e223d1f94da808e02f"),
										},
									},
								},
							},
						},
					},
					{
						Namespace: "",
						Kind:      "NodeInfo",
						Name:      "kind-control-plane",
						Report: types.Report{
							ArtifactType: "vm",
							ArtifactName: "kind-control-plane",
							Metadata: types.Metadata{
								OS: &ftypes.OS{
									Family: "ubuntu",
									Name:   "21.04",
								},
								Properties: []types.Property{
									{
										Key:   "node_role",
										Value: "master",
									},
									{
										Key:   "host_name",
										Value: "kind-control-plane",
									},
									{
										Key:   "kernel_version",
										Value: "6.2.13-300.fc38.aarch64",
									},
									{
										Key:   "operating_system",
										Value: "linux",
									},
									{
										Key:   "architecture",
										Value: "arm64",
									},
								},
							},
							Results: types.Results{
								{
									Target: "os-packages",
									Class:  types.ClassOSPkg,
									Type:   "ubuntu",
								},
								{
									Target: "node-core-components",
									Class:  types.ClassLangPkg,
									Type:   "golang",
									Packages: ftypes.Packages{
										{
											Name:    "containerd",
											Version: "1.5.2",
										},
										{
											Name:    "kubelet",
											Version: "1.21.1",
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
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
