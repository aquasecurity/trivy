package gke

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/gke"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  gke.GKE
	}{
		{
			name: "separately defined pool",
			terraform: `
resource "google_service_account" "default" {
  account_id   = "service-account-id"
  display_name = "Service Account"
}

resource "google_container_cluster" "example" {
  name = "my-gke-cluster"

  node_config {
    metadata = {
      disable-legacy-endpoints = true
    }
  }

  pod_security_policy_config {
    enabled = "true"
  }

  enable_legacy_abac    = "true"
  enable_shielded_nodes = "true"

  remove_default_node_pool = true
  initial_node_count       = 1
  monitoring_service       = "monitoring.googleapis.com/kubernetes"
  logging_service          = "logging.googleapis.com/kubernetes"

  master_auth {
    client_certificate_config {
      issue_client_certificate = true
    }
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.10.128.0/24"
      display_name = "internal"
    }
  }

  resource_labels = {
    "env" = "staging"
  }

  private_cluster_config {
    enable_private_nodes = true
  }

  network_policy {
    enabled = true
  }

  ip_allocation_policy {}

  enable_autopilot = true

  datapath_provider = "ADVANCED_DATAPATH"

  cluster_autoscaling {
    enabled = true
    auto_provisioning_defaults {
      service_account  = "test"
	  image_type = "COS_CONTAINERD"
	  management {
        auto_repair  = true
        auto_upgrade = true
      }
    }
  }
}

resource "google_container_node_pool" "primary_preemptible_nodes" {
  cluster    = google_container_cluster.example.name
  node_count = 1

  node_config {
    service_account = google_service_account.default.email
    metadata = {
      disable-legacy-endpoints = true
    }
    image_type = "COS_CONTAINERD"
    workload_metadata_config {
      mode = "GCE_METADATA"
    }
  }
  management {
    auto_repair  = true
    auto_upgrade = true
  }
}
`,
			expected: gke.GKE{
				Clusters: []gke.Cluster{
					{
						NodeConfig: gke.NodeConfig{
							ImageType: iacTypes.StringTest("COS_CONTAINERD"),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								NodeMetadata: iacTypes.StringTest("GCE_METADATA"),
							},
						},
						AutoScaling: gke.AutoScaling{
							Enabled: iacTypes.BoolTest(true),
							AutoProvisioningDefaults: gke.AutoProvisioningDefaults{
								ImageType:      iacTypes.StringTest("COS_CONTAINERD"),
								ServiceAccount: iacTypes.StringTest("test"),
								Management: gke.Management{
									EnableAutoRepair:  iacTypes.BoolTest(true),
									EnableAutoUpgrade: iacTypes.BoolTest(true),
								},
							},
						},
						NodePools: []gke.NodePool{
							{
								Management: gke.Management{
									EnableAutoRepair:  iacTypes.BoolTest(true),
									EnableAutoUpgrade: iacTypes.BoolTest(true),
								},
								NodeConfig: gke.NodeConfig{
									ImageType: iacTypes.StringTest("COS_CONTAINERD"),
									WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
										NodeMetadata: iacTypes.StringTest("GCE_METADATA"),
									},
								},
							},
						},
						IPAllocationPolicy: gke.IPAllocationPolicy{
							Enabled: iacTypes.BoolTest(true),
						},
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Enabled: iacTypes.BoolTest(true),
							CIDRs: []iacTypes.StringValue{
								iacTypes.StringTest("10.10.128.0/24"),
							},
						},
						NetworkPolicy: gke.NetworkPolicy{
							Enabled: iacTypes.BoolTest(true),
						},
						DatapathProvider: iacTypes.StringTest("ADVANCED_DATAPATH"),
						PrivateCluster: gke.PrivateCluster{
							EnablePrivateNodes: iacTypes.BoolTest(true),
						},
						LoggingService:    iacTypes.StringTest("logging.googleapis.com/kubernetes"),
						MonitoringService: iacTypes.StringTest("monitoring.googleapis.com/kubernetes"),
						MasterAuth: gke.MasterAuth{
							ClientCertificate: gke.ClientCertificate{
								IssueCertificate: iacTypes.BoolTest(true),
							},
						},
						EnableShieldedNodes: iacTypes.BoolTest(true),
						EnableLegacyABAC:    iacTypes.BoolTest(true),
						ResourceLabels: iacTypes.MapTest(map[string]string{
							"env": "staging",
						}),
						RemoveDefaultNodePool: iacTypes.BoolTest(true),
						EnableAutpilot:        iacTypes.BoolTest(true),
					},
				},
			},
		},
		{
			name: "default node pool",
			terraform: `
resource "google_container_cluster" "example" {
  node_config {
    service_account = "service-account"
    metadata = {
      disable-legacy-endpoints = "true"
    }
    image_type = "COS"
    workload_metadata_config {
      mode = "GCE_METADATA"
    }
  }
} 
`,
			expected: gke.GKE{
				Clusters: []gke.Cluster{
					{
						NodeConfig: gke.NodeConfig{
							ImageType: iacTypes.StringTest("COS"),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								NodeMetadata: iacTypes.StringTest("GCE_METADATA"),
							},
							ServiceAccount: iacTypes.StringTest("service-account"),
						},

						IPAllocationPolicy: gke.IPAllocationPolicy{},
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							CIDRs: []iacTypes.StringValue{},
						},
						NetworkPolicy:     gke.NetworkPolicy{},
						DatapathProvider:  iacTypes.StringTest("DATAPATH_PROVIDER_UNSPECIFIED"),
						PrivateCluster:    gke.PrivateCluster{},
						LoggingService:    iacTypes.StringTest("logging.googleapis.com/kubernetes"),
						MonitoringService: iacTypes.StringTest("monitoring.googleapis.com/kubernetes"),
						MasterAuth: gke.MasterAuth{
							ClientCertificate: gke.ClientCertificate{},
						},
						EnableShieldedNodes: iacTypes.BoolTest(true),
						ResourceLabels:      iacTypes.MapTest(make(map[string]string)),
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
resource "google_container_cluster" "example" {

  node_config {
    metadata = {
      disable-legacy-endpoints = true
    }
  }
  pod_security_policy_config {
    enabled = "true"
  }

  enable_legacy_abac    = "true"
  enable_shielded_nodes = "true"

  remove_default_node_pool = true
  monitoring_service       = "monitoring.googleapis.com/kubernetes"
  logging_service          = "logging.googleapis.com/kubernetes"

  master_auth {
    client_certificate_config {
      issue_client_certificate = true
    }
  }

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block = "10.10.128.0/24"
    }
  }

  resource_labels = {
    "env" = "staging"
  }

  private_cluster_config {
    enable_private_nodes = true
  }

  network_policy {
    enabled = true
  }
  ip_allocation_policy {}
}

resource "google_container_node_pool" "primary_preemptible_nodes" {
  cluster = google_container_cluster.example.name

  node_config {
    metadata = {
      disable-legacy-endpoints = true
    }
    service_account = google_service_account.default.email
    image_type      = "COS_CONTAINERD"

    workload_metadata_config {
      mode = "GCE_METADATA"
    }
  }
  management {
    auto_repair  = true
    auto_upgrade = true
  }
}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	cluster := adapted.Clusters[0]
	nodePool := cluster.NodePools[0]

	assert.Equal(t, 2, cluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 44, cluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 49, cluster.NodeConfig.Metadata.Range().GetStartLine())
	assert.Equal(t, 59, cluster.NodeConfig.Metadata.Range().GetEndLine())

	assert.Equal(t, 50, cluster.NodeConfig.EnableLegacyEndpoints.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 52, cluster.NodeConfig.EnableLegacyEndpoints.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, cluster.EnableLegacyABAC.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, cluster.EnableLegacyABAC.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, cluster.EnableShieldedNodes.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, cluster.EnableShieldedNodes.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, cluster.RemoveDefaultNodePool.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, cluster.RemoveDefaultNodePool.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, cluster.MonitoringService.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, cluster.MonitoringService.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, cluster.LoggingService.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, cluster.LoggingService.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 20, cluster.MasterAuth.Metadata.Range().GetStartLine())
	assert.Equal(t, 24, cluster.MasterAuth.Metadata.Range().GetEndLine())

	assert.Equal(t, 21, cluster.MasterAuth.ClientCertificate.Metadata.Range().GetStartLine())
	assert.Equal(t, 23, cluster.MasterAuth.ClientCertificate.Metadata.Range().GetEndLine())

	assert.Equal(t, 22, cluster.MasterAuth.ClientCertificate.IssueCertificate.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, cluster.MasterAuth.ClientCertificate.IssueCertificate.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, cluster.MasterAuthorizedNetworks.Metadata.Range().GetStartLine())
	assert.Equal(t, 30, cluster.MasterAuthorizedNetworks.Metadata.Range().GetEndLine())

	assert.Equal(t, 28, cluster.MasterAuthorizedNetworks.CIDRs[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, cluster.MasterAuthorizedNetworks.CIDRs[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 32, cluster.ResourceLabels.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, cluster.ResourceLabels.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 36, cluster.PrivateCluster.Metadata.Range().GetStartLine())
	assert.Equal(t, 38, cluster.PrivateCluster.Metadata.Range().GetEndLine())

	assert.Equal(t, 37, cluster.PrivateCluster.EnablePrivateNodes.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 37, cluster.PrivateCluster.EnablePrivateNodes.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 40, cluster.NetworkPolicy.Metadata.Range().GetStartLine())
	assert.Equal(t, 42, cluster.NetworkPolicy.Metadata.Range().GetEndLine())

	assert.Equal(t, 41, cluster.NetworkPolicy.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 41, cluster.NetworkPolicy.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 43, cluster.IPAllocationPolicy.Metadata.Range().GetStartLine())
	assert.Equal(t, 43, cluster.IPAllocationPolicy.Metadata.Range().GetEndLine())

	assert.Equal(t, 46, nodePool.Metadata.Range().GetStartLine())
	assert.Equal(t, 64, nodePool.Metadata.Range().GetEndLine())

	assert.Equal(t, 49, nodePool.NodeConfig.Metadata.Range().GetStartLine())
	assert.Equal(t, 59, nodePool.NodeConfig.Metadata.Range().GetEndLine())

	assert.Equal(t, 53, nodePool.NodeConfig.ServiceAccount.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 53, nodePool.NodeConfig.ServiceAccount.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 54, nodePool.NodeConfig.ImageType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 54, nodePool.NodeConfig.ImageType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 56, nodePool.NodeConfig.WorkloadMetadataConfig.Metadata.Range().GetStartLine())
	assert.Equal(t, 58, nodePool.NodeConfig.WorkloadMetadataConfig.Metadata.Range().GetEndLine())

	assert.Equal(t, 57, nodePool.NodeConfig.WorkloadMetadataConfig.NodeMetadata.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 57, nodePool.NodeConfig.WorkloadMetadataConfig.NodeMetadata.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 60, nodePool.Management.Metadata.Range().GetStartLine())
	assert.Equal(t, 63, nodePool.Management.Metadata.Range().GetEndLine())

	assert.Equal(t, 61, nodePool.Management.EnableAutoRepair.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 61, nodePool.Management.EnableAutoRepair.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 62, nodePool.Management.EnableAutoUpgrade.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 62, nodePool.Management.EnableAutoUpgrade.GetMetadata().Range().GetEndLine())

}
