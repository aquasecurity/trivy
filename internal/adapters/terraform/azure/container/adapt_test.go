package container

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/container"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  container.KubernetesCluster
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_kubernetes_cluster" "example" {
				private_cluster_enabled = true

				network_profile {
				  network_policy = "calico"
				}

				api_server_access_profile {

					authorized_ip_ranges = [
					"1.2.3.4/32"
					]
		
				}

				addon_profile {
					oms_agent {
						enabled = true
					}
				}

				role_based_access_control {
					enabled = true
				}
			}
`,
			expected: container.KubernetesCluster{
				Metadata: defsecTypes.NewTestMetadata(),
				NetworkProfile: container.NetworkProfile{
					Metadata:      defsecTypes.NewTestMetadata(),
					NetworkPolicy: defsecTypes.String("calico", defsecTypes.NewTestMetadata()),
				},
				EnablePrivateCluster: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				APIServerAuthorizedIPRanges: []defsecTypes.StringValue{
					defsecTypes.String("1.2.3.4/32", defsecTypes.NewTestMetadata()),
				},
				AddonProfile: container.AddonProfile{
					Metadata: defsecTypes.NewTestMetadata(),
					OMSAgent: container.OMSAgent{
						Metadata: defsecTypes.NewTestMetadata(),
						Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
				RoleBasedAccessControl: container.RoleBasedAccessControl{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "rbac with a new syntax",
			terraform: `
			resource "azurerm_kubernetes_cluster" "example" {
				role_based_access_control_enabled = true
			}
`,
			expected: container.KubernetesCluster{
				Metadata: defsecTypes.NewTestMetadata(),
				NetworkProfile: container.NetworkProfile{
					Metadata:      defsecTypes.NewTestMetadata(),
					NetworkPolicy: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
				EnablePrivateCluster: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				AddonProfile: container.AddonProfile{
					Metadata: defsecTypes.NewTestMetadata(),
					OMSAgent: container.OMSAgent{
						Metadata: defsecTypes.NewTestMetadata(),
						Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
				RoleBasedAccessControl: container.RoleBasedAccessControl{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_kubernetes_cluster" "example" {
			}
`,
			expected: container.KubernetesCluster{
				Metadata: defsecTypes.NewTestMetadata(),
				NetworkProfile: container.NetworkProfile{
					Metadata:      defsecTypes.NewTestMetadata(),
					NetworkPolicy: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
				EnablePrivateCluster: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				AddonProfile: container.AddonProfile{
					Metadata: defsecTypes.NewTestMetadata(),
					OMSAgent: container.OMSAgent{
						Metadata: defsecTypes.NewTestMetadata(),
						Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
				RoleBasedAccessControl: container.RoleBasedAccessControl{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "rbac off with k8s rbac on",
			terraform: `
resource "azurerm_kubernetes_cluster" "misreporting_example" {
    role_based_access_control_enabled = true # Enable k8s RBAC
    azure_active_directory_role_based_access_control {
      managed = true # Enable AKS-managed Azure AAD integration 
      azure_rbac_enabled = false # Explicitly disable Azure RBAC for Kubernetes Authorization
    }
 }
`,
			expected: container.KubernetesCluster{
				Metadata: defsecTypes.NewTestMetadata(),
				NetworkProfile: container.NetworkProfile{
					Metadata:      defsecTypes.NewTestMetadata(),
					NetworkPolicy: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
				EnablePrivateCluster: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				AddonProfile: container.AddonProfile{
					Metadata: defsecTypes.NewTestMetadata(),
					OMSAgent: container.OMSAgent{
						Metadata: defsecTypes.NewTestMetadata(),
						Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
				RoleBasedAccessControl: container.RoleBasedAccessControl{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_kubernetes_cluster" "example" {
		private_cluster_enabled = true

		network_profile {
		  network_policy = "calico"
		}
        
		api_server_access_profile {

		    authorized_ip_ranges = [
			"1.2.3.4/32"
		    ]

		}

		addon_profile {
			oms_agent {
				enabled = true
			}
		}

		role_based_access_control {
			enabled = true
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.KubernetesClusters, 1)
	cluster := adapted.KubernetesClusters[0]

	assert.Equal(t, 3, cluster.EnablePrivateCluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, cluster.EnablePrivateCluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.NetworkProfile.Metadata.Range().GetStartLine())
	assert.Equal(t, 7, cluster.NetworkProfile.Metadata.Range().GetEndLine())

	assert.Equal(t, 6, cluster.NetworkProfile.NetworkPolicy.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, cluster.NetworkProfile.NetworkPolicy.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, cluster.APIServerAuthorizedIPRanges[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, cluster.APIServerAuthorizedIPRanges[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, cluster.AddonProfile.Metadata.Range().GetStartLine())
	assert.Equal(t, 21, cluster.AddonProfile.Metadata.Range().GetEndLine())

	assert.Equal(t, 18, cluster.AddonProfile.OMSAgent.Metadata.Range().GetStartLine())
	assert.Equal(t, 20, cluster.AddonProfile.OMSAgent.Metadata.Range().GetEndLine())

	assert.Equal(t, 19, cluster.AddonProfile.OMSAgent.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, cluster.AddonProfile.OMSAgent.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, cluster.RoleBasedAccessControl.Metadata.Range().GetStartLine())
	assert.Equal(t, 25, cluster.RoleBasedAccessControl.Metadata.Range().GetEndLine())

	assert.Equal(t, 24, cluster.RoleBasedAccessControl.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, cluster.RoleBasedAccessControl.Enabled.GetMetadata().Range().GetEndLine())
}

func TestWithLocals(t *testing.T) {
	src := `
	variable "ip_whitelist" {
  description = "IP Ranges with allowed access."
  type        = list(string)
  default     = ["1.2.3.4"]
}

locals {
  ip_whitelist = concat(var.ip_whitelist, split(",", data.azurerm_public_ip.build_agents.ip_address))
}

resource "azurerm_kubernetes_cluster" "aks" {
  # not working
  api_server_access_profile {
   authorized_ip_ranges = local.ip_whitelist
  }
  # working
  api_server_access_profile {
   authorized_ip_ranges = concat(var.ip_whitelist, split(",", data.azurerm_public_ip.example.ip_address))
  }
}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.KubernetesClusters, 1)
	cluster := adapted.KubernetesClusters[0]
	require.Len(t, cluster.APIServerAuthorizedIPRanges, 1)
	assert.False(t, cluster.APIServerAuthorizedIPRanges[0].GetMetadata().IsResolvable())
}
