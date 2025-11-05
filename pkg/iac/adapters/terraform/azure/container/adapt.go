package container

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/container"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) container.Container {
	return container.Container{
		KubernetesClusters: adaptClusters(modules),
	}
}

func adaptClusters(modules terraform.Modules) []container.KubernetesCluster {
	var clusters []container.KubernetesCluster

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_kubernetes_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptCluster(resource *terraform.Block) container.KubernetesCluster {

	cluster := container.KubernetesCluster{
		Metadata: resource.GetMetadata(),
		NetworkProfile: container.NetworkProfile{
			Metadata:      resource.GetMetadata(),
			NetworkPolicy: iacTypes.StringDefault("", resource.GetMetadata()),
		},
		EnablePrivateCluster:        iacTypes.BoolDefault(false, resource.GetMetadata()),
		APIServerAuthorizedIPRanges: nil,
		AzurePolicyEnabled:          iacTypes.BoolDefault(false, resource.GetMetadata()),
		DiskEncryptionSetID:         iacTypes.StringDefault("", resource.GetMetadata()),
		AgentPools:                  []container.AgentPool{},
		RoleBasedAccessControl: container.RoleBasedAccessControl{
			Metadata: resource.GetMetadata(),
			Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		AddonProfile: container.AddonProfile{
			Metadata: resource.GetMetadata(),
			OMSAgent: container.OMSAgent{
				Metadata: resource.GetMetadata(),
				Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			},
			AzurePolicy: container.AzurePolicy{
				Metadata: resource.GetMetadata(),
				Enabled:  iacTypes.BoolDefault(false, resource.GetMetadata()),
			},
		},
	}

	networkProfileBlock := resource.GetBlock("network_profile")
	if networkProfileBlock.IsNotNil() {
		networkPolicyAttr := networkProfileBlock.GetAttribute("network_policy")
		cluster.NetworkProfile.Metadata = networkProfileBlock.GetMetadata()
		cluster.NetworkProfile.NetworkPolicy = networkPolicyAttr.AsStringValueOrDefault("", networkProfileBlock)
	}

	privateClusterEnabledAttr := resource.GetAttribute("private_cluster_enabled")
	cluster.EnablePrivateCluster = privateClusterEnabledAttr.AsBoolValueOrDefault(false, resource)

	if apiServerBlock := resource.GetBlock("api_server_access_profile"); apiServerBlock.IsNotNil() {
		authorizedIPRangesAttr := apiServerBlock.GetAttribute("authorized_ip_ranges")
		cluster.APIServerAuthorizedIPRanges = authorizedIPRangesAttr.AsStringValues()
	}

	addonProfileBlock := resource.GetBlock("addon_profile")
	if addonProfileBlock.IsNotNil() {
		cluster.AddonProfile.Metadata = addonProfileBlock.GetMetadata()
		omsAgentBlock := addonProfileBlock.GetBlock("oms_agent")
		if omsAgentBlock.IsNotNil() {
			cluster.AddonProfile.OMSAgent.Metadata = omsAgentBlock.GetMetadata()
			enabledAttr := omsAgentBlock.GetAttribute("enabled")
			cluster.AddonProfile.OMSAgent.Enabled = enabledAttr.AsBoolValueOrDefault(false, omsAgentBlock)
		}
		azurePolicyBlock := addonProfileBlock.GetBlock("azure_policy")
		if azurePolicyBlock.IsNotNil() {
			cluster.AddonProfile.AzurePolicy.Metadata = azurePolicyBlock.GetMetadata()
			enabledAttr := azurePolicyBlock.GetAttribute("enabled")
			cluster.AddonProfile.AzurePolicy.Enabled = enabledAttr.AsBoolValueOrDefault(false, azurePolicyBlock)
		}
	}

	// >= azurerm 2.97.0
	if omsAgentBlock := resource.GetBlock("oms_agent"); omsAgentBlock.IsNotNil() {
		cluster.AddonProfile.OMSAgent.Metadata = omsAgentBlock.GetMetadata()
		cluster.AddonProfile.OMSAgent.Enabled = iacTypes.Bool(true, omsAgentBlock.GetMetadata())
	}

	// azurerm < 2.99.0
	if rbacBlock := resource.GetBlock("role_based_access_control"); rbacBlock.IsNotNil() {
		rbEnabledAttr := rbacBlock.GetAttribute("enabled")
		cluster.RoleBasedAccessControl.Metadata = rbacBlock.GetMetadata()
		cluster.RoleBasedAccessControl.Enabled = rbEnabledAttr.AsBoolValueOrDefault(false, rbacBlock)
	}

	if rbacEnabledAttr := resource.GetAttribute("role_based_access_control_enabled"); rbacEnabledAttr.IsNotNil() {
		// azurerm >= 2.99.0
		cluster.RoleBasedAccessControl.Metadata = rbacEnabledAttr.GetMetadata()
		cluster.RoleBasedAccessControl.Enabled = rbacEnabledAttr.AsBoolValueOrDefault(false, resource)
	}

	if block := resource.GetBlock("azure_active_directory_role_based_access_control"); block.IsNotNil() {
		enabledAttr := block.GetAttribute("azure_rbac_enabled")
		if enabledAttr.IsNotNil() {
			if !cluster.RoleBasedAccessControl.Enabled.IsTrue() {
				cluster.RoleBasedAccessControl.Metadata = block.GetMetadata()
				cluster.RoleBasedAccessControl.Enabled = enabledAttr.AsBoolValueOrDefault(false, block)
			}
		}

	}

	// azurerm >= 3.0.0 - new syntax for azure policy
	if azurePolicyEnabledAttr := resource.GetAttribute("azure_policy_enabled"); azurePolicyEnabledAttr.IsNotNil() {
		cluster.AzurePolicyEnabled = azurePolicyEnabledAttr.AsBoolValueOrDefault(false, resource)
	}

	if diskEncryptionSetIDAttr := resource.GetAttribute("disk_encryption_set_id"); diskEncryptionSetIDAttr.IsNotNil() {
		cluster.DiskEncryptionSetID = diskEncryptionSetIDAttr.AsStringValueOrDefault("", resource)
	}

	cluster.AgentPools = adaptAgentPools(resource)

	return cluster
}

func adaptAgentPools(resource *terraform.Block) []container.AgentPool {
	var pools []container.AgentPool

	if defaultNodePoolBlock := resource.GetBlock("default_node_pool"); defaultNodePoolBlock.IsNotNil() {
		pools = append(pools, adaptAgentPool(defaultNodePoolBlock))
	}

	return pools
}

func adaptAgentPool(block *terraform.Block) container.AgentPool {
	return container.AgentPool{
		Metadata:            block.GetMetadata(),
		DiskEncryptionSetID: block.GetAttribute("disk_encryption_set_id").AsStringValueOrDefault("", block),
		NodeType:            block.GetAttribute("type").AsStringValueOrDefault("VirtualMachineScaleSets", block),
	}
}
