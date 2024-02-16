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
	}

	// >= azurerm 2.97.0
	if omsAgentBlock := resource.GetBlock("oms_agent"); omsAgentBlock.IsNotNil() {
		cluster.AddonProfile.OMSAgent.Metadata = omsAgentBlock.GetMetadata()
		cluster.AddonProfile.OMSAgent.Enabled = iacTypes.Bool(true, omsAgentBlock.GetMetadata())
	}

	// azurerm < 2.99.0
	if resource.HasChild("role_based_access_control") {
		roleBasedAccessControlBlock := resource.GetBlock("role_based_access_control")
		rbEnabledAttr := roleBasedAccessControlBlock.GetAttribute("enabled")
		cluster.RoleBasedAccessControl.Metadata = roleBasedAccessControlBlock.GetMetadata()
		cluster.RoleBasedAccessControl.Enabled = rbEnabledAttr.AsBoolValueOrDefault(false, roleBasedAccessControlBlock)
	}
	if resource.HasChild("role_based_access_control_enabled") {
		// azurerm >= 2.99.0
		roleBasedAccessControlEnabledAttr := resource.GetAttribute("role_based_access_control_enabled")
		cluster.RoleBasedAccessControl.Metadata = roleBasedAccessControlEnabledAttr.GetMetadata()
		cluster.RoleBasedAccessControl.Enabled = roleBasedAccessControlEnabledAttr.AsBoolValueOrDefault(false, resource)
	}

	if resource.HasChild("azure_active_directory_role_based_access_control") {
		azureRoleBasedAccessControl := resource.GetBlock("azure_active_directory_role_based_access_control")
		if azureRoleBasedAccessControl.IsNotNil() {
			enabledAttr := azureRoleBasedAccessControl.GetAttribute("azure_rbac_enabled")
			if !cluster.RoleBasedAccessControl.Enabled.IsTrue() {
				cluster.RoleBasedAccessControl.Metadata = azureRoleBasedAccessControl.GetMetadata()
				cluster.RoleBasedAccessControl.Enabled = enabledAttr.AsBoolValueOrDefault(false, azureRoleBasedAccessControl)
			}
		}
	}
	return cluster
}
