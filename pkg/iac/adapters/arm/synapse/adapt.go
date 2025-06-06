package synapse

import (
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/synapse"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(deployment azure.Deployment) synapse.Synapse {
	return synapse.Synapse{
		Workspaces: adaptWorkspaces(deployment),
	}
}

func adaptWorkspaces(deployment azure.Deployment) []synapse.Workspace {
	return lo.Map(deployment.GetResourcesByType("Microsoft.Synapse/workspaces"),
		func(r azure.Resource, _ int) synapse.Workspace { return adaptWorkspace(r) },
	)
}

func adaptWorkspace(resource azure.Resource) synapse.Workspace {
	return synapse.Workspace{
		Metadata:                    resource.Metadata,
		EnableManagedVirtualNetwork: adaptManagedVirtualNetwork(resource),
	}
}

func adaptManagedVirtualNetwork(resource azure.Resource) types.BoolValue {
	prop := resource.Properties.GetMapValue("managedVirtualNetwork")
	if !prop.IsNull() {
		return types.Bool(prop.EqualTo("default"), prop.GetMetadata())
	}
	return types.BoolDefault(false, resource.Metadata)
}
