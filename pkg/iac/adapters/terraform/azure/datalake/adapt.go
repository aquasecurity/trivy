package datalake

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/datalake"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) datalake.DataLake {
	return datalake.DataLake{
		Stores: adaptStores(modules),
	}
}

func adaptStores(modules terraform.Modules) []datalake.Store {
	var stores []datalake.Store

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_data_lake_store") {
			stores = append(stores, adaptStore(resource))
		}
	}
	return stores
}

func adaptStore(resource *terraform.Block) datalake.Store {
	store := datalake.Store{
		Metadata:         resource.GetMetadata(),
		EnableEncryption: types.BoolDefault(true, resource.GetMetadata()),
	}
	encryptionStateAttr := resource.GetAttribute("encryption_state")
	if encryptionStateAttr.Equals("Disabled") {
		store.EnableEncryption = types.Bool(false, encryptionStateAttr.GetMetadata())
	} else if encryptionStateAttr.Equals("Enabled") {
		store.EnableEncryption = types.Bool(true, encryptionStateAttr.GetMetadata())
	}
	return store
}
