package synapse

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/synapse"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) synapse.Synapse {
	return synapse.Synapse{
		Workspaces: adaptWorkspaces(modules),
	}
}

func adaptWorkspaces(modules terraform.Modules) []synapse.Workspace {
	var workspaces []synapse.Workspace
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_synapse_workspace") {
			workspaces = append(workspaces, adaptWorkspace(resource))
		}
	}
	return workspaces
}

func adaptWorkspace(resource *terraform.Block) synapse.Workspace {
	enableManagedVNAttr := resource.GetAttribute("managed_virtual_network_enabled")
	enableManagedVNVal := enableManagedVNAttr.AsBoolValueOrDefault(false, resource)

	return synapse.Workspace{
		Metadata:                    resource.GetMetadata(),
		EnableManagedVirtualNetwork: enableManagedVNVal,
	}
}
