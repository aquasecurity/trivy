package datafactory

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/datafactory"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

func Adapt(deployment azure.Deployment) datafactory.DataFactory {

	return datafactory.DataFactory{
		DataFactories: adaptDataFactories(deployment),
	}
}

func adaptDataFactories(deployment azure.Deployment) (factories []datafactory.Factory) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.DataFactory/factories") {
		factories = append(factories, adaptDataFactory(resource))
	}
	return factories
}

func adaptDataFactory(resource azure.Resource) datafactory.Factory {
	return datafactory.Factory{
		Metadata:            resource.Metadata,
		EnablePublicNetwork: resource.Properties.GetMapValue("publicNetworkAccess").AsBoolValue(true, resource.Metadata),
	}
}
