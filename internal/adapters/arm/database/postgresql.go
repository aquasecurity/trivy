package database

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/azure"
)

func adaptPostgreSQLServers(deployment azure.Deployment) (databases []database.PostgreSQLServer) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.DBforPostgreSQL/servers") {
		databases = append(databases, adaptPostgreSQLServer(resource, deployment))
	}

	return databases
}

func adaptPostgreSQLServer(resource azure.Resource, deployment azure.Deployment) database.PostgreSQLServer {
	return database.PostgreSQLServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata:                  resource.Metadata,
			EnableSSLEnforcement:      resource.Properties.GetMapValue("sslEnforcement").AsBoolValue(false, resource.Metadata),
			MinimumTLSVersion:         resource.Properties.GetMapValue("minimalTlsVersion").AsStringValue("TLSEnforcementDisabled", resource.Metadata),
			EnablePublicNetworkAccess: resource.Properties.GetMapValue("publicNetworkAccess").AsBoolValue(false, resource.Metadata),
			FirewallRules:             addFirewallRule(resource),
		},
		Config: adaptPostgreSQLConfiguration(resource, deployment),
	}
}

func adaptPostgreSQLConfiguration(resource azure.Resource, deployment azure.Deployment) database.PostgresSQLConfig {

	parent := fmt.Sprintf("%s/", resource.Name.AsString())

	config := database.PostgresSQLConfig{
		Metadata:             resource.Metadata,
		LogCheckpoints:       defsecTypes.BoolDefault(false, resource.Metadata),
		ConnectionThrottling: defsecTypes.BoolDefault(false, resource.Metadata),
		LogConnections:       defsecTypes.BoolDefault(false, resource.Metadata),
	}

	for _, configuration := range deployment.GetResourcesByType("Microsoft.DBforPostgreSQL/servers/configurations") {
		if strings.HasPrefix(configuration.Name.AsString(), parent) {
			val := configuration.Properties.GetMapValue("value")
			if strings.HasSuffix(configuration.Name.AsString(), "log_checkpoints") {
				config.LogCheckpoints = val.AsBoolValue(false, configuration.Metadata)
				continue
			}
			if strings.HasSuffix(configuration.Name.AsString(), "log_connections") {
				config.LogConnections = val.AsBoolValue(false, configuration.Metadata)
				continue
			}
			if strings.HasSuffix(configuration.Name.AsString(), "connection_throttling") {
				config.ConnectionThrottling = val.AsBoolValue(false, configuration.Metadata)
				continue
			}
		}
	}

	return config
}
