package container

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/container"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected container.Container
	}{
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.ContainerService/managedClusters",
      "properties": {
        "networkProfile": {
          "networkPolicy": "calico"
        },
        "apiServerAccessProfile": {
          "enablePrivateCluster": true,
          "authorizedIPRanges": ["1.2.3.4/32"]
        },
        "enableRBAC": true,
        "addonProfiles": {
          "omsagent": { "enabled": true },
          "azurepolicy": { "enabled": true }
        },
        "diskEncryptionSetID": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des",
        "agentPoolProfiles": [
          {
            "name": "nodepool1",
            "type": "VirtualMachineScaleSets",
            "diskEncryptionSetID": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des-pool"
          }
        ]
      }
    }
  ]
}`,
			expected: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						NetworkProfile: container.NetworkProfile{
							NetworkPolicy: types.StringTest("calico"),
						},
						EnablePrivateCluster:        types.BoolTest(true),
						APIServerAuthorizedIPRanges: []types.StringValue{types.StringTest("1.2.3.4/32")},
						RoleBasedAccessControl: container.RoleBasedAccessControl{
							Enabled: types.BoolTest(true),
						},
						AddonProfile: container.AddonProfile{
							OMSAgent: container.OMSAgent{
								Enabled: types.BoolTest(true),
							},
							AzurePolicy: container.AzurePolicy{
								Enabled: types.BoolTest(true),
							},
						},
						DiskEncryptionSetID: types.StringTest("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des"),
						AgentPools: []container.AgentPool{
							{
								DiskEncryptionSetID: types.StringTest("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des-pool"),
								NodeType:            types.StringTest("VirtualMachineScaleSets"),
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			source: `{
  "resources": [
    {
      "type": "Microsoft.ContainerService/managedClusters",
      "properties": {
      }
    }
  ]
}`,
			expected: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						NetworkProfile: container.NetworkProfile{
							NetworkPolicy: types.StringTest(""),
						},
						EnablePrivateCluster:        types.BoolTest(false),
						APIServerAuthorizedIPRanges: nil,
						RoleBasedAccessControl: container.RoleBasedAccessControl{
							Enabled: types.BoolTest(false),
						},
						AddonProfile: container.AddonProfile{
							OMSAgent: container.OMSAgent{
								Enabled: types.BoolTest(false),
							},
							AzurePolicy: container.AzurePolicy{
								Enabled: types.BoolTest(false),
							},
						},
						DiskEncryptionSetID: types.StringTest(""),
						AgentPools:          nil,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}
