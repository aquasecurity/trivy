package gke

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/gke"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/test/testutil"
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
						Metadata: defsecTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  defsecTypes.NewTestMetadata(),
							ImageType: defsecTypes.String("COS_CONTAINERD", defsecTypes.NewTestMetadata()),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     defsecTypes.NewTestMetadata(),
								NodeMetadata: defsecTypes.String("GCE_METADATA", defsecTypes.NewTestMetadata()),
							},
							ServiceAccount:        defsecTypes.String("", defsecTypes.NewTestMetadata()),
							EnableLegacyEndpoints: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
						NodePools: []gke.NodePool{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:          defsecTypes.NewTestMetadata(),
									EnableAutoRepair:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
									EnableAutoUpgrade: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
								},
								NodeConfig: gke.NodeConfig{
									Metadata:  defsecTypes.NewTestMetadata(),
									ImageType: defsecTypes.String("COS_CONTAINERD", defsecTypes.NewTestMetadata()),
									WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
										Metadata:     defsecTypes.NewTestMetadata(),
										NodeMetadata: defsecTypes.String("GCE_METADATA", defsecTypes.NewTestMetadata()),
									},
									ServiceAccount:        defsecTypes.String("", defsecTypes.NewTestMetadata()),
									EnableLegacyEndpoints: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
								},
							},
						},
						IPAllocationPolicy: gke.IPAllocationPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							CIDRs: []defsecTypes.StringValue{
								defsecTypes.String("10.10.128.0/24", defsecTypes.NewTestMetadata()),
							},
						},
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
						PrivateCluster: gke.PrivateCluster{
							Metadata:           defsecTypes.NewTestMetadata(),
							EnablePrivateNodes: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
						LoggingService:    defsecTypes.String("logging.googleapis.com/kubernetes", defsecTypes.NewTestMetadata()),
						MonitoringService: defsecTypes.String("monitoring.googleapis.com/kubernetes", defsecTypes.NewTestMetadata()),
						MasterAuth: gke.MasterAuth{
							Metadata: defsecTypes.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         defsecTypes.NewTestMetadata(),
								IssueCertificate: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							},
							Username: defsecTypes.String("", defsecTypes.NewTestMetadata()),
							Password: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
						EnableShieldedNodes: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						EnableLegacyABAC:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						ResourceLabels: defsecTypes.Map(map[string]string{
							"env": "staging",
						}, defsecTypes.NewTestMetadata()),
						RemoveDefaultNodePool: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						EnableAutpilot:        defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
      disable-legacy-endpoints = true
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
						Metadata: defsecTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  defsecTypes.NewTestMetadata(),
							ImageType: defsecTypes.String("COS", defsecTypes.NewTestMetadata()),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     defsecTypes.NewTestMetadata(),
								NodeMetadata: defsecTypes.String("GCE_METADATA", defsecTypes.NewTestMetadata()),
							},
							ServiceAccount:        defsecTypes.String("service-account", defsecTypes.NewTestMetadata()),
							EnableLegacyEndpoints: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},

						IPAllocationPolicy: gke.IPAllocationPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							CIDRs:    []defsecTypes.StringValue{},
						},
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: defsecTypes.NewTestMetadata(),
							Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
						PrivateCluster: gke.PrivateCluster{
							Metadata:           defsecTypes.NewTestMetadata(),
							EnablePrivateNodes: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
						LoggingService:    defsecTypes.String("logging.googleapis.com/kubernetes", defsecTypes.NewTestMetadata()),
						MonitoringService: defsecTypes.String("monitoring.googleapis.com/kubernetes", defsecTypes.NewTestMetadata()),
						MasterAuth: gke.MasterAuth{
							Metadata: defsecTypes.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         defsecTypes.NewTestMetadata(),
								IssueCertificate: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
							Username: defsecTypes.String("", defsecTypes.NewTestMetadata()),
							Password: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
						EnableShieldedNodes:   defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						EnableLegacyABAC:      defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						ResourceLabels:        defsecTypes.Map(map[string]string{}, defsecTypes.NewTestMetadata()),
						RemoveDefaultNodePool: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
