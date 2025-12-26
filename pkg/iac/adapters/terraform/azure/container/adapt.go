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
		if block := addonProfileBlock.GetBlock("oms_agent"); block.IsNotNil() {
			cluster.AddonProfile.OMSAgent = container.OMSAgent{
				Metadata: block.GetMetadata(),
				Enabled:  block.GetAttribute("enabled").AsBoolValueOrDefault(false, block),
			}
		}

		if block := addonProfileBlock.GetBlock("azure_policy"); block.IsNotNil() {
			cluster.AddonProfile.AzurePolicy = container.AzurePolicy{
				Metadata: block.GetMetadata(),
				Enabled:  block.GetAttribute("enabled").AsBoolValueOrDefault(false, block),
			}
		}
	}

	// >= azurerm 2.97.0
	if block := resource.GetBlock("oms_agent"); block.IsNotNil() {
		cluster.AddonProfile.OMSAgent = container.OMSAgent{
			Metadata: block.GetMetadata(),
			Enabled:  iacTypes.Bool(true, block.GetMetadata()),
		}
	}

	// azurerm >= 3.0.0 - new syntax for azure policy
	if attr := resource.GetAttribute("azure_policy_enabled"); attr.IsNotNil() {
		cluster.AddonProfile.AzurePolicy = container.AzurePolicy{
			Metadata: attr.GetMetadata(),
			Enabled:  attr.AsBoolValueOrDefault(false, resource),
		}
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
