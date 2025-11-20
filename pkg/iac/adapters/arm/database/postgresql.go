package database

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptPostgreSQLServers(deployment azure.Deployment) (databases []database.PostgreSQLServer) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.DBforPostgreSQL/servers") {
		databases = append(databases, adaptPostgreSQLServer(resource, deployment))
	}

	return databases
}

func adaptPostgreSQLServer(resource azure.Resource, deployment azure.Deployment) database.PostgreSQLServer {
	properties := resource.Properties
	geoRedundantBackup := properties.GetMapValue("storageProfile").GetMapValue("geoRedundantBackup")
	geoRedundantBackupEnabled := geoRedundantBackup.AsStringValue("Disabled", resource.Metadata)
	
	threatDetectionPolicy := adaptThreatDetectionPolicy(resource, deployment)

	return database.PostgreSQLServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata:                  resource.Metadata,
			EnableSSLEnforcement:      properties.GetMapValue("sslEnforcement").AsBoolValue(false, resource.Metadata),
			MinimumTLSVersion:         properties.GetMapValue("minimalTlsVersion").AsStringValue("TLSEnforcementDisabled", resource.Metadata),
			EnablePublicNetworkAccess: properties.GetMapValue("publicNetworkAccess").AsBoolValue(false, resource.Metadata),
			FirewallRules:             addFirewallRule(resource),
		},
		Config:                    adaptPostgreSQLConfiguration(resource, deployment),
		GeoRedundantBackupEnabled: iacTypes.Bool(geoRedundantBackupEnabled.EqualTo("Enabled"), geoRedundantBackup.GetMetadata()),
		ThreatDetectionPolicy:      threatDetectionPolicy,
	}
}

func adaptPostgreSQLConfiguration(resource azure.Resource, deployment azure.Deployment) database.PostgresSQLConfig {

	parent := fmt.Sprintf("%s/", resource.Name.AsString())

	config := database.PostgresSQLConfig{
		Metadata:             resource.Metadata,
		LogCheckpoints:       iacTypes.BoolDefault(false, resource.Metadata),
		ConnectionThrottling: iacTypes.BoolDefault(false, resource.Metadata),
		LogConnections:       iacTypes.BoolDefault(false, resource.Metadata),
		LogDisconnections:    iacTypes.BoolDefault(false, resource.Metadata),
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
			if strings.HasSuffix(configuration.Name.AsString(), "log_disconnections") {
				config.LogDisconnections = val.AsBoolValue(false, configuration.Metadata)
				continue
			}
		}
	}

	return config
}

func adaptThreatDetectionPolicy(resource azure.Resource, deployment azure.Deployment) database.ThreatDetectionPolicy {
	// Threat detection policy is typically configured via securityAlertPolicies in ARM
	// For PostgreSQL, it may be in properties or as a separate resource
	properties := resource.Properties
	threatDetectionEnabled := properties.GetMapValue("threatDetectionPolicy").GetMapValue("state")
	
	if threatDetectionEnabled.IsNil() {
		// Try alternative property paths
		threatDetectionEnabled = properties.GetMapValue("securityAlertPolicy").GetMapValue("state")
	}
	
	enabled := false
	metadata := resource.Metadata
	if !threatDetectionEnabled.IsNil() {
		state := threatDetectionEnabled.AsStringValue("Disabled", resource.Metadata)
		enabled = state.EqualTo("Enabled")
		metadata = threatDetectionEnabled.GetMetadata()
	}

	return database.ThreatDetectionPolicy{
		Metadata: metadata,
		Enabled:  iacTypes.Bool(enabled, metadata),
	}
}
