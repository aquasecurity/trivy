package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

func Adapt(deployment azure.Deployment) database.Database {
	return database.Database{
		MSSQLServers:      adaptMSSQLServers(deployment),
		MariaDBServers:    adaptMariaDBServers(deployment),
		MySQLServers:      adaptMySQLServers(deployment),
		PostgreSQLServers: adaptPostgreSQLServers(deployment),
	}
}

func adaptMySQLServers(deployment azure.Deployment) (mysqlDbServers []database.MySQLServer) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.DBforMySQL/servers") {
		mysqlDbServers = append(mysqlDbServers, adaptMySQLServer(resource, deployment))
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
			FirewallRules:             addFirewallRule(resource),
		},
	}
}
