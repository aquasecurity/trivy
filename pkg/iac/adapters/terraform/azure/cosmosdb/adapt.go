package cosmosdb

import (
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/cosmosdb"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) cosmosdb.CosmosDB {
	return cosmosdb.CosmosDB{
		Accounts: adaptCosmosDBAccounts(modules),
	}
}

func adaptCosmosDBAccounts(modules terraform.Modules) []cosmosdb.Account {
	var cosmosDBAccounts []cosmosdb.Account
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_cosmosdb_account") {
			cosmosDBAccounts = append(cosmosDBAccounts, adaptCosmosDBAccount(resource))
		}
	}
	return cosmosDBAccounts
}

func adaptCosmosDBAccount(resource *terraform.Block) cosmosdb.Account {
	// ip_range_filter is a list of strings in Terraform
	ipRangeFilterAttr := resource.GetAttribute("ip_range_filter")
	var ipRangeFilterVal []iacTypes.StringValue
	if ipRangeFilterAttr.IsNil() {
		ipRangeFilterVal = []iacTypes.StringValue{}
	} else {
		switch ipRangeFilterAttr.Type() {
		case cty.String:
			ipRangeFilterVal = []iacTypes.StringValue{ipRangeFilterAttr.AsStringValueOrDefault("", resource)}
		default:
			ipRangeFilterVal = ipRangeFilterAttr.AsStringValues()
		}
	}

	return cosmosdb.Account{
		Metadata:      resource.GetMetadata(),
		IPRangeFilter: ipRangeFilterVal,
	}
}
