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

func adaptMariaDBServer(resource azure.Resource, deployment azure.Deployment) database.MariaDBServer {
	return database.MariaDBServer{
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
