package datalake

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/datalake"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

func Adapt(deployment azure.Deployment) datalake.DataLake {

	return datalake.DataLake{
		Stores: adaptStores(deployment),
	}
}

func adaptStores(deployment azure.Deployment) (stores []datalake.Store) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.DataLakeStore/accounts") {
		stores = append(stores, adaptStore(resource))
	}

	return stores
}

func adaptStore(resource azure.Resource) datalake.Store {
	return datalake.Store{
		Metadata: resource.Metadata,
		// TODO: encryptionState is string
		// https://learn.microsoft.com/en-us/azure/templates/microsoft.datalakestore/accounts?pivots=deployment-language-arm-template#createdatalakestoreaccountpropertiesordatalakestoreaccountproperties-1
		EnableEncryption: resource.Properties.GetMapValue("encryptionState").AsBoolValue(false, resource.Metadata),
	}
}
