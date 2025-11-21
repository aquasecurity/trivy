package cosmosdb

import (
	"strings"

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

	tagsAttr := resource.GetAttribute("tags")
	var tagsVal iacTypes.MapValue
	if tagsAttr.IsNil() {
		tagsVal = iacTypes.MapDefault(make(map[string]string), resource.GetMetadata())
	} else {
		tagsVal = tagsAttr.AsMapValue()
	}

	// ip_range_filter is a list of strings in Terraform
	ipRangeFilterAttr := resource.GetAttribute("ip_range_filter")
	var ipRangeFilterVal iacTypes.StringValue
	if ipRangeFilterAttr.IsNil() {
		ipRangeFilterVal = iacTypes.StringDefault("", resource.GetMetadata())
	} else {
		// Handle as list of strings and join with commas
		ipRanges := ipRangeFilterAttr.AsStringValues()
		if len(ipRanges) == 0 {
			ipRangeFilterVal = iacTypes.StringDefault("", resource.GetMetadata())
		} else {
			var ranges []string
			for _, r := range ipRanges {
				ranges = append(ranges, r.Value())
			}
			ipRangeFilterVal = iacTypes.String(strings.Join(ranges, ","), ipRangeFilterAttr.GetMetadata())
		}
	}

	return cosmosdb.Account{
		Metadata:      resource.GetMetadata(),
		IPRangeFilter: ipRangeFilterVal,
		Tags:          tagsVal,
	}
}
