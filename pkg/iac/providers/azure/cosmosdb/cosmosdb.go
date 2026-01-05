package cosmosdb

import iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

type CosmosDB struct {
	Accounts []Account
}

type Account struct {
	Metadata      iacTypes.Metadata
	IPRangeFilter []iacTypes.StringValue
}
