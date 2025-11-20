package database

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(deployment azure.Deployment) database.Database {
	return database.Database{
		MSSQLServers:      adaptMSSQLServers(deployment),
		MariaDBServers:    adaptMariaDBServers(deployment),
		MySQLServers:      adaptMySQLServers(deployment),
		PostgreSQLServers: adaptPostgreSQLServers(deployment),
		CosmosDBAccounts:  adaptCosmosDBAccounts(deployment),
	}
}

func adaptMySQLServers(deployment azure.Deployment) (mysqlDbServers []database.MySQLServer) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.DBforMySQL/servers") {
		mysqlDbServers = append(mysqlDbServers, adaptMySQLServer(resource, deployment))
	}
	return mysqlDbServers
}

func adaptMySQLServer(resource azure.Resource, _ azure.Deployment) database.MySQLServer {
	return database.MySQLServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata:                  resource.Metadata,
			EnableSSLEnforcement:      resource.Properties.GetMapValue("sslEnforcement").AsBoolValue(false, resource.Metadata),
			MinimumTLSVersion:         resource.Properties.GetMapValue("minimalTlsVersion").AsStringValue("TLSEnforcementDisabled", resource.Metadata),
			EnablePublicNetworkAccess: resource.Properties.GetMapValue("publicNetworkAccess").AsBoolValue(false, resource.Metadata),
			FirewallRules:             addFirewallRule(resource),
		},
	}
}

func adaptCosmosDBAccounts(deployment azure.Deployment) []database.CosmosDBAccount {
	var cosmosDBAccounts []database.CosmosDBAccount
	for _, resource := range deployment.GetResourcesByType("Microsoft.DocumentDB/databaseAccounts") {
		cosmosDBAccounts = append(cosmosDBAccounts, adaptCosmosDBAccount(resource))
	}
	return cosmosDBAccounts
}

func adaptCosmosDBAccount(resource azure.Resource) database.CosmosDBAccount {
	properties := resource.Properties
	
	// ipRangeFilter can be a string or array in ARM templates
	ipRangeFilter := properties.GetMapValue("ipRangeFilter")
	var ipRangeFilterVal iacTypes.StringValue
	if !ipRangeFilter.IsNil() {
		if ipRangeFilter.IsString() {
			ipRangeFilterVal = ipRangeFilter.AsStringValue("", resource.Metadata)
		} else if ipRangeFilter.IsList() {
			// If it's an array, join the values
			var ranges []string
			for _, v := range ipRangeFilter.AsList() {
				ranges = append(ranges, v.AsStringValue("", ipRangeFilter.GetMetadata()).Value())
			}
			ipRangeFilterVal = iacTypes.String(strings.Join(ranges, ","), ipRangeFilter.GetMetadata())
		} else {
			ipRangeFilterVal = iacTypes.StringDefault("", resource.Metadata)
		}
	} else {
		ipRangeFilterVal = iacTypes.StringDefault("", resource.Metadata)
	}

	// Tags
	tags := resource.Tags
	tagsMap := make(map[string]string)
	if !tags.IsNil() {
		for key, val := range tags.AsMap() {
			tagsMap[key] = val.AsStringValue("", tags.GetMetadata()).Value()
		}
	}
	tagsVal := iacTypes.MapDefault(tagsMap, resource.Metadata)

	return database.CosmosDBAccount{
		Metadata:      resource.Metadata,
		IPRangeFilter: ipRangeFilterVal,
		Tags:          tagsVal,
	}
}
