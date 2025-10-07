package datafactory

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/datafactory"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) datafactory.DataFactory {
	return datafactory.DataFactory{
		DataFactories: adaptFactories(modules),
	}
}

func adaptFactories(modules terraform.Modules) []datafactory.Factory {
	var factories []datafactory.Factory

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_data_factory") {
			factories = append(factories, adaptFactory(resource))
		}
	}
	return factories
}

func adaptFactory(resource *terraform.Block) datafactory.Factory {
	enablePublicNetworkAttr := resource.GetAttribute("public_network_enabled")
	enablePublicNetworkVal := enablePublicNetworkAttr.AsBoolValueOrDefault(true, resource)

	return datafactory.Factory{
		Metadata:            resource.GetMetadata(),
		EnablePublicNetwork: enablePublicNetworkVal,
	}
}
