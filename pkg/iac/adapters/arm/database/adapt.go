package database

import (
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
	}
}

const mysqlServerType = "Microsoft.DBforMySQL/servers"

func adaptMySQLServers(deployment azure.Deployment) (mysqlDbServers []database.MySQLServer) {
	for _, resource := range deployment.GetResourcesByType(mysqlServerType) {
		mysqlDbServers = append(mysqlDbServers, adaptMySQLServer(resource, deployment))
	}
	if rules := orphanFirewallRules(deployment, mysqlServerType); len(rules) > 0 {
		metadata := iacTypes.NewUnmanagedMetadata()
		mysqlDbServers = append(mysqlDbServers, database.MySQLServer{Metadata: metadata, Server: orphanServer(metadata, rules)})
	}
	return mysqlDbServers
}

func adaptMySQLServer(resource azure.Resource, deployment azure.Deployment) database.MySQLServer {
	return database.MySQLServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata:                  resource.Metadata,
			EnableSSLEnforcement:      resource.Properties.GetMapValue("sslEnforcement").AsBoolValue(false, resource.Metadata),
			MinimumTLSVersion:         resource.Properties.GetMapValue("minimalTlsVersion").AsStringValue("TLSEnforcementDisabled", resource.Metadata),
			EnablePublicNetworkAccess: resource.Properties.GetMapValue("publicNetworkAccess").AsBoolValue(false, resource.Metadata),
			FirewallRules:             addFirewallRule(resource, deployment),
		},
	}
}
