package datalake

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/datalake"
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
	encryptionStateAttr := resource.GetAttribute("encryption_state")

	if encryptionStateAttr.Equals("Disabled") {
		return datalake.Store{
			EnableEncryption: types.Bool(false, resource.GetMetadata()),
		}
	}
	return datalake.Store{
		Metadata:         resource.GetMetadata(),
		EnableEncryption: types.Bool(true, resource.GetMetadata()),
	}
}
