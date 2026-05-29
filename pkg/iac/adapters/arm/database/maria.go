package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

func adaptMariaDBServers(deployment azure.Deployment) (mariaDbServers []database.MariaDBServer) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.DBforMariaDB/servers") {
		mariaDbServers = append(mariaDbServers, adaptMariaDBServer(resource, deployment))
	}
	return mariaDbServers

}

func adaptMariaDBServer(resource azure.Resource, _ azure.Deployment) database.MariaDBServer {
	return database.MariaDBServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata:                  resource.Metadata,
			EnableSSLEnforcement:      resource.Properties.GetMapValue("sslEnforcement").AsBoolValue(),
			MinimumTLSVersion:         resource.Properties.GetMapValue("minimalTlsVersion").AsStringValue("TLSEnforcementDisabled"),
			EnablePublicNetworkAccess: resource.Properties.GetMapValue("publicNetworkAccess").AsBoolValue(),
			FirewallRules:             addFirewallRule(resource),
		},
	}
}
