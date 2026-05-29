package container

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/container"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

func Adapt(deployment azure.Deployment) container.Container {
	return container.Container{
		KubernetesClusters: adaptKubernetesClusters(deployment),
	}
}

func adaptKubernetesClusters(deployment azure.Deployment) []container.KubernetesCluster {
	var clusters []container.KubernetesCluster
	for _, resource := range deployment.GetResourcesByType("Microsoft.ContainerService/managedClusters") {
		props := resource.Properties

		cluster := container.KubernetesCluster{
			Metadata: resource.Metadata,
			NetworkProfile: container.NetworkProfile{
				Metadata:      props.GetMapValue("networkProfile").GetMetadata(),
				NetworkPolicy: props.GetMapValue("networkProfile").GetMapValue("networkPolicy").AsStringValue(""),
			},
			EnablePrivateCluster:        props.GetMapValue("apiServerAccessProfile").GetMapValue("enablePrivateCluster").AsBoolValue(false),
			APIServerAuthorizedIPRanges: nil, // Extracted below
			RoleBasedAccessControl: container.RoleBasedAccessControl{
				Metadata: props.GetMetadata(),
				Enabled:  props.GetMapValue("enableRBAC").AsBoolValue(false),
			},
			AddonProfile: container.AddonProfile{
				Metadata: props.GetMapValue("addonProfiles").GetMetadata(),
				OMSAgent: container.OMSAgent{
					Metadata: props.GetMapValue("addonProfiles").GetMapValue("omsagent").GetMetadata(),
					Enabled:  props.GetMapValue("addonProfiles").GetMapValue("omsagent").GetMapValue("enabled").AsBoolValue(false),
				},
				AzurePolicy: container.AzurePolicy{
					Metadata: props.GetMapValue("addonProfiles").GetMapValue("azurepolicy").GetMetadata(),
					Enabled:  props.GetMapValue("addonProfiles").GetMapValue("azurepolicy").GetMapValue("enabled").AsBoolValue(false),
				},
			},
			DiskEncryptionSetID: props.GetMapValue("diskEncryptionSetID").AsStringValue(""),
			AgentPools:          adaptAgentPools(resource),
		}

		// API Server Authorized IP Ranges
		if ranges := props.GetMapValue("apiServerAccessProfile").GetMapValue("authorizedIPRanges"); !ranges.IsNull() {
			cluster.APIServerAuthorizedIPRanges = ranges.AsStringValuesList("")
		}

		clusters = append(clusters, cluster)
	}
	return clusters
}

func adaptAgentPools(resource azure.Resource) []container.AgentPool {
	var pools []container.AgentPool
	// agentPoolProfiles is an array of objects
	profiles := resource.Properties.GetMapValue("agentPoolProfiles")
	if profiles.Kind == azure.KindArray {
		for _, profile := range profiles.AsList() {
			pools = append(pools, container.AgentPool{
				Metadata:            profile.GetMetadata(),
				DiskEncryptionSetID: profile.GetMapValue("diskEncryptionSetID").AsStringValue(""),
				NodeType:            profile.GetMapValue("type").AsStringValue("VirtualMachineScaleSets"),
			})
		}
	}
	return pools
}
